#!/usr/bin/env bash
#
# check.sh — every check the Go tree gets, in one place.
#
#   bash check.sh            # everything CI runs for the Go lane
#   bash check.sh packages   # only the "does this lane actually cover anything" guard
#   bash check.sh go         # packages + gofmt + build + vet + boundary + test
#   bash check.sh boundary   # only the reference-boundary gates
#   bash check.sh parity     # the PARITY lane: proves every @test in the frozen bats corpus is
#                            # accounted for EXACTLY ONCE by a PORTED:/N/A: inventory line in the
#                            # Go tree, and that every PORTED target names a test that really
#                            # runs. It is the evidence that deleting the bash tree loses
#                            # nothing, so it runs on every change rather than once - and it
#                            # keeps running AFTER that deletion, from the committed manifest.
#   bash check.sh release    # the RELEASE lane: builds the published platform matrix with the
#                            # release flags, grades the artifacts, and proves byte
#                            # reproducibility by building the whole matrix a second time from
#                            # a different source path with a cold cache. Needs only the go
#                            # toolchain - it is in CI's go job and in `all`, deliberately, so
#                            # a broken release script is found on a pull request rather than
#                            # at a tag.
#   bash check.sh selfcheck  # THE GATE'S OWN GATE: re-runs the graders under a hostile Go
#                            # environment and requires each one to still reach its true answer.
#                            # `go run` honours GOFLAGS, and GOFLAGS carries -exec and -ldflags,
#                            # so an inherited one can replace a grader with /usr/bin/true or
#                            # rewrite the constant it grades against — and the stage still
#                            # prints OK. See the block above check_selfcheck.
#   bash check.sh acceptance # the REAL-DAEMON lane: re-measures the daemon behaviors the
#                            # hermetic fake asserts, against a live local daemon (needs Docker
#                            # running, and two small pulls). The behaviors it CANNOT reach are
#                            # named in the lane's own comments (the private-mode connect
#                            # refusal, the helper success path pending the pinned probe
#                            # image). Opt-in - NOT in CI's default path; run before every
#                            # wave gate, divergences fixed in fake+client.
#
# WHY THIS FILE EXISTS. CI and any future release gate must run identical checks; spelling the
# commands out twice guarantees they drift, and the direction they drift is always the same —
# the release lane ends up laxer than the PR lane. One script, N callers. (Adapted from the
# family's first Go module, which established this shape.)
#
# THE PACKAGE-COUNT GUARD IS THE POINT OF THE `packages` STAGE. `go test ./...` over a
# directory that matches no packages prints nothing and exits 0 — a CI job wired to the wrong
# path is indistinguishable from a green suite, permanently and silently. Same for a run that
# compiles packages but executes no tests. Both are asserted with explicit floors.
set -euo pipefail

# CDPATH= on the inner cd: a caller with CDPATH set makes `cd` PRINT the directory it landed
# in, which lands inside the command substitution. `--` guards a path beginning with a dash.
cd "$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# The script's own name, for the stage that re-enters it (check_selfcheck). We have just cd'd to
# its directory, so the basename is enough and survives whatever relative path it was invoked by.
SELF="./$(basename -- "${BASH_SOURCE[0]}")"

# THE GO ENVIRONMENT IS OWNED BY THIS SCRIPT, PROCESS-WIDE — NOT INVOCATION BY INVOCATION.
#
# `go run` honours GOFLAGS, and GOFLAGS carries `-exec`. An inherited
# `GOFLAGS=-exec=/usr/bin/true` therefore makes every `go run` below BUILD its grader and then
# execute /usr/bin/true instead of it: the stage prints nothing, exits 0, and this script prints
# `check.sh: OK` having graded nothing. Measured on this tree with a real parity hole present —
# `bash check.sh parity` exited 1, the identical command under that GOFLAGS exited 0. GOFLAGS
# carries `-ldflags` as well, so `-ldflags=-X=main.manifestSHA256=<digest>` REPLACES the corpus
# digest tools/parity-audit pins against, and an edited manifest with its matching digest would
# pass without the source pin ever changing.
#
# SET ONCE, HERE, RATHER THAN ON THE INVOCATIONS THAT LOOKED IMPORTANT — because guarding
# invocation by invocation is precisely what produced that bypass. Two `go test` calls in this
# file carried the prefix and the `go run` that did the actual grading did not; the same asymmetry
# existed in tools/parity-audit.sh, whose four witness commands were guarded and whose grader was
# not. Nothing could tell the difference: a neutered grader and a clean tree exit 0 alike.
#
# BOTH ASSIGNMENTS ARE LOAD-BEARING, AND THE FIRST DOES NOT IMPLY THE SECOND. Go treats an EMPTY
# environment variable as UNSET and falls back to the go env FILE — measured: with `GOFLAGS=''`
# exported and a file setting GOFLAGS, `go env GOFLAGS` reports the FILE's value. So `GOFLAGS=''`
# closes only the variable, and GOENV=off is what closes the file. Delete either and the bypass
# is back; `bash check.sh selfcheck` is what says so, on both channels separately.
#
# GOWORK=off is the third of the same kind, and it is not decorative: a `go.work` in ANY ancestor
# directory — or named by GOWORK — is ambient file state the go command reads without being asked.
# Measured: with a workspace active that does not `use` this directory, `go list ./...` refuses
# outright, so every stage below would report a failure that says nothing about this tree; and its
# `replace` directives decide which copy of a dependency is compiled into these graders. This is a
# single-module repository — there is no workspace here to honour, and selfcheck probes this
# channel too.
#
# NOT PINNED, deliberately. GOOS/GOARCH: an inherited pair cannot make a grader report success
# falsely — `go run` refuses to run a cross-compiled binary and `go test`/`go list` fail loudly —
# and tools/build-release.sh legitimately sets them per target. GOTOOLCHAIN, GOROOT, PATH and
# GOMODCACHE: those choose WHICH toolchain and WHICH sources run, so no assignment inside a script
# the same environment can already replace would mean anything; build-release.sh pins GOTOOLCHAIN
# because two Go releases emit different bytes, which is a reproducibility question, not this one.
export GOFLAGS=''
export GOENV=off
export GOWORK=off

# Floors, not exact counts: the tree grows a package per port task, and each task raises these
# two literals in its commit. Overridable ONLY so a test harness can prove the guard refuses.
MIN_PACKAGES="${MIN_PACKAGES:-30}"
MIN_TESTED_PACKAGES="${MIN_TESTED_PACKAGES:-30}"

# The reference-boundary rules, one per line: `<guarded-import-path>:<Identifier>=<allowed
# import path>[,<more allowed>]`. Each rule is
# added by the task that creates the boundary and NEVER removed — these survive the bash
# cutover; a once-run audit protects nothing afterwards. The gate resolves REFERENCES via the
# AST (selector and identifier use, not call syntax), so a function VALUE of a guarded symbol
# is caught too, and the DEFINING package is not exempt (an in-package bare reference trips
# the rule unless that package is allowlisted explicitly) — see tools/boundary-gate.
BOUNDARY_RULES=(
  # staging-boundary (Task 8): the restore staging store is constructed ONLY by the backup
  # module — a lifecycle path that could open staging would treat a not-yet-verified restore
  # as live state.
  "mythicalos.ai/ctl/internal/ledger:OpenStaging=mythicalos.ai/ctl/internal/backup"
  # parse-verified-boundary (Tasks 10-11): authenticated documents are constructible only by
  # the trust acceptors — lifecycle code must be unable to hold a policy or manifest that did
  # not pass through the chain.
  "mythicalos.ai/ctl/internal/policy:ParseVerified=mythicalos.ai/ctl/internal/trust"
  "mythicalos.ai/ctl/internal/manifest:ParseVerified=mythicalos.ai/ctl/internal/trust"
  # raw-lines boundary (Task 12): the trust module keeps its own record shape (docids carry
  # ':', which the typed editors' field grammar refuses) — nothing else may bypass them.
  "method:ReplaceLines=mythicalos.ai/ctl/internal/trust"
  # mutator-boundary (Task 14): every engine mutation requires the family lock, and the
  # Mutator is constructible ONLY by the runtime facade — probes, verbs and data movement
  # reach mutations through it, so no code path can hold an unlocked mutation door.
  "mythicalos.ai/ctl/internal/engine:NewMutator=mythicalos.ai/ctl/internal/runtime"
  # sole-launch (Task 15): product-spec construction and the create call are pinned to the
  # facade's launch path — a second launch site would put the mount/publish/secret rules back
  # at its call sites, which is the one thing the launch module exists to prevent.
  "mythicalos.ai/ctl/internal/engine:NewContainerSpec=mythicalos.ai/ctl/internal/runtime"
  "method:ContainerCreate=internal/runtime/launch.go"
)

die() {
  printf 'check.sh: ERROR: %s\n' "$*" >&2
  exit 1
}

RELEASE_OUTDIR=''
SELFCHECK_TMPDIR=''
# ONE EXIT TRAP FOR THE WHOLE SCRIPT. A second `trap ... EXIT` REPLACES the first rather than
# adding to it, so a per-stage trap stops cleaning up the moment a later stage installs its own —
# and `all` runs several stages in one process.
# shellcheck disable=SC2317  # invoked via trap
cleanup_tmp() {
  if [ -n "${RELEASE_OUTDIR:-}" ]; then
    rm -rf "$RELEASE_OUTDIR"
  fi
  if [ -n "${SELFCHECK_TMPDIR:-}" ]; then
    rm -rf "$SELFCHECK_TMPDIR"
  fi
}
trap cleanup_tmp EXIT
step() { printf '\n=== %s ===\n' "$*"; }

check_packages() {
  step "packages"
  command -v go > /dev/null 2>&1 || die "no go toolchain on PATH"
  go version
  local listed count
  listed="$(go list ./...)"
  count="$(printf '%s\n' "$listed" | awk 'NF {n++} END {print n + 0}')"
  printf '%s\n' "$listed"
  # A FLOOR THAT SITS BELOW REALITY STILL PASSES, AND THAT IS HOW IT DIES. Measured three times
  # on the Wave 5-8 integration: parallel branches each add a package and each raise this literal
  # by one, and git merges N identical one-line raises into ONE — the last time with no conflict at
  # all, because both sides agreed on a number that was already stale. The floor then sits below
  # the tree, reports OK, and is silently unable to notice the next package that stops being
  # tested. So drift is now REPORTED rather than tolerated: it is not fatal (a floor is meant to be
  # a floor, and a branch legitimately adds packages before it bumps this), but it can no longer
  # happen quietly.
  if [ "$count" -gt "$MIN_PACKAGES" ]; then
    printf 'check.sh: NOTE: %s packages present, floor is %s — raise MIN_PACKAGES to %s.\n' \
      "$count" "$MIN_PACKAGES" "$count" >&2
  fi
  if [ "$count" -lt "$MIN_PACKAGES" ]; then
    die "go list ./... matched $count package(s), expected at least $MIN_PACKAGES.
   Either this lane is pointed at the wrong directory — in which case every 'go test' below is
   a no-op that exits 0 — or packages were deleted and this floor needs a deliberate change."
  fi
  printf 'packages: %s (floor %s)\n' "$count" "$MIN_PACKAGES"
}

# Counts PACKAGES THAT ACTUALLY RAN A TEST, from `go test -json` run events — not `ok` lines.
# The `ok` count is defeated by one flag: `-run '^$'` matches no tests, executes nothing, and
# still prints `ok` for every package.
count_ok() {
  grep -a '"Action":"run"' \
    | grep -ao '"Package":"[^"]*"' \
    | sort -u \
    | awk 'END {print NR + 0}'
}

assert_tested_floor() { # assert_tested_floor <count>
  if [ "$1" -lt "$MIN_TESTED_PACKAGES" ]; then
    die "only $1 package(s) actually ran a test, expected at least $MIN_TESTED_PACKAGES.
   A suite where every package says '[no test files]' also exits 0 — that is the state this
   floor exists to catch."
  fi
  printf 'tested packages: %s (floor %s)\n' "$1" "$MIN_TESTED_PACKAGES"
}

check_boundary() {
  step "boundary"
  if [ "${#BOUNDARY_RULES[@]}" -eq 0 ]; then
    printf 'boundary: no rules yet (rules land with the boundaries they guard)\n'
    return 0
  fi
  # This is THE line the bypass was demonstrated on. GOFLAGS/GOENV/GOWORK are owned process-wide
  # at the top of this file — see that block for what an inherited one does to it, and
  # `bash check.sh selfcheck` for the probe that proves the ownership holds.
  go run ./tools/boundary-gate "${BOUNDARY_RULES[@]}"
}

# THE RELEASE LANE RUNS FROM THIS FILE FOR THE REASON IN THE HEADER. A release gate spelled out
# in the release workflow instead drifts away from the pull-request lane, and it drifts lax:
# nobody notices a check that stopped running on a path that runs a few times a year. So the
# release build is a stage here, called identically by CI and by a person.
#
# The synthetic version is deliberately NOT internal/version's default. If the -X symbol path
# ever stops resolving, a build stamped with the default would still print something plausible
# and the round-trip would pass; stamping something the source cannot produce on its own makes
# that failure loud.
check_release() {
  step "release (reproducible build)"
  # NOT `local`: the EXIT trap fires after this function has returned, and a local would be out
  # of scope by then -- the cleanup would run against an empty path and silently remove nothing,
  # leaving a multi-megabyte directory behind on every run.
  RELEASE_OUTDIR="$(mktemp -d "${TMPDIR:-/tmp}/mctl-release-check.XXXXXX")"
  bash tools/build-release.sh --repro 0.0.0-checksh "$RELEASE_OUTDIR"
}

# THE PARITY LANE. Delegated to tools/parity-audit.sh for the same reason the release lane is
# delegated to tools/build-release.sh: the toolchain driving belongs in a script and the grading
# belongs in a separately-testable Go program. See that script's header for what it proves.
check_parity() {
  step "parity (bats corpus vs the Go inventory)"
  bash tools/parity-audit.sh
}

# THE SELF-CHECK. A GRADER THAT CAN BE SWITCHED OFF FROM THE ENVIRONMENT IS NOT A GRADER.
#
# `go run` honours GOFLAGS, and GOFLAGS carries `-exec`: with `GOFLAGS=-exec=/usr/bin/true` in the
# environment, `go run ./tools/boundary-gate ...` BUILDS the gate and then runs /usr/bin/true
# INSTEAD of it. The stage prints nothing, exits 0, and this script prints OK having graded
# nothing. Measured on this tree, on `boundary` and on `parity`, the latter with a real parity hole
# present: `bash check.sh parity` exited 1 and the same command under that GOFLAGS exited 0.
# GOFLAGS carries `-ldflags` too, so `-ldflags=-X=main.manifestSHA256=<digest>` REPLACES the corpus
# digest the parity auditor pins against — an edited manifest and its matching digest would pass
# without the source pin ever changing.
#
# THIS STAGE EXISTS BECAUSE THE GUARD WAS ONCE APPLIED PER INVOCATION. tools/parity-audit.sh
# cleared GOFLAGS/GOENV on its four witness commands and not on the `go run` two lines below them
# that did the actual grading; check.sh cleared them on `go test` and not on the boundary gate.
# Nothing anywhere could tell the difference, because a neutered grader and a clean tree exit 0
# alike and print almost the same thing. A guard nobody tests is how that arrived.
#
# WHAT A PROBE ASSERTS, AND WHY IT IS A PAIR. Each stage is run under a hostile Go environment and
# required to reach its TRUE answer: exit 0 AND the grader's own verdict line present in the
# output. Requiring only "does not report success" would be satisfied by a fix that broke every
# stage unconditionally; requiring only exit 0 is satisfied by the bypass itself. It is the two
# together that mean the grader ran and answered.
#
# AND THE PAYLOAD IS PROVED HOSTILE BEFORE ANY OF THEM. If `-exec` ever stopped reaching `go run`,
# every probe below would pass while proving nothing, and this stage would become exactly the kind
# of ornament it exists to prevent. So each channel first runs an UNGUARDED `go run` that MUST
# fail — the boundary gate with no rules, which refuses — and requires the payload to turn it into
# an exit 0.
SELFCHECK_RC=0
# 64 hex characters, so it is the shape of a digest and not merely a string the pin would reject
# for its length. Nothing can hash to it.
SELFCHECK_BOGUS_DIGEST='deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
# tests/smoke.sh needs a payload of its OWN — see the note beside its probes. The symbol is
# tools/build-release.sh's VERSION_SYMBOL by necessity rather than by copy: if it ever stops
# resolving, the -X does nothing, the control probe below stops seeing this string and says so.
SELFCHECK_VERSION_SYMBOL='mythicalos.ai/ctl/internal/version.Version'
SELFCHECK_BOGUS_VERSION='SELFCHECK-NOT-A-SEMVER'

selfcheck_fail() {
  printf '  FAIL  %s\n' "$*" >&2
  SELFCHECK_RC=1
}
selfcheck_dump() {
  printf '%s\n' "$1" | sed -e 's/^/          | /' >&2
}

# selfcheck_probe <label> <ok|refuse|neutered> <needle> <command...>
#
#   ok        the command must exit 0 AND print <needle> — the grader ran and gave its verdict
#   refuse    the command must exit non-zero AND print <needle> — assert WHICH refusal, or the
#             probe stops testing its own premise
#   neutered  the command must exit 0 — this is the positive control on the payload, not a check
#             of the tree; <needle> is ignored
#   breaks    the command must exit NON-ZERO — the other positive control, for a payload whose
#             effect is to make an unguarded go command refuse rather than grade nothing
selfcheck_probe() {
  local label="$1" want="$2" needle="$3"
  shift 3
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  case "$want" in
    ok)
      if [ "$rc" -ne 0 ]; then
        selfcheck_fail "$label: exited $rc. Under a hostile Go environment the stage must still
          reach its TRUE answer — a guard that fails everything unconditionally is not a guard."
        selfcheck_dump "$out"
        return 0
      fi
      if ! printf '%s\n' "$out" | grep -qaF -- "$needle"; then
        selfcheck_fail "$label: exited 0 but never printed the grader's own verdict ($needle) —
          THE GRADER DID NOT RUN. An inherited GOFLAGS/GOENV reached that invocation and replaced
          it; own them at the top of the script that makes it, not on the invocations that looked
          important."
        selfcheck_dump "$out"
        return 0
      fi
      ;;
    refuse)
      if [ "$rc" -eq 0 ]; then
        selfcheck_fail "$label: exited 0, but this invocation MUST be refused — the grader's
          non-zero exit never reached the caller, so an inherited GOFLAGS/GOENV neutered it."
        selfcheck_dump "$out"
        return 0
      fi
      if ! printf '%s\n' "$out" | grep -qaF -- "$needle"; then
        selfcheck_fail "$label: refused (exit $rc) but not for the expected reason ($needle)."
        selfcheck_dump "$out"
        return 0
      fi
      ;;
    neutered)
      if [ "$rc" -ne 0 ]; then
        selfcheck_fail "$label: exited $rc. The payload is supposed to NEUTER an unguarded
          'go run' and it did not, so every probe in this channel would pass while proving
          nothing. Fix the payload before trusting this stage."
        selfcheck_dump "$out"
        return 0
      fi
      ;;
    breaks)
      if [ "$rc" -eq 0 ]; then
        selfcheck_fail "$label: exited 0. The payload is supposed to make an unguarded go command
          REFUSE and it did not, so every probe in this channel would pass while proving nothing.
          Fix the payload before trusting this stage."
        selfcheck_dump "$out"
        return 0
      fi
      ;;
    *) die "selfcheck_probe: unknown expectation: $want" ;;
  esac
  printf '  ok    %s\n' "$label"
}

# The --write-manifest branch of tools/parity-audit.sh is a SECOND `go run` in that script, on its
# own line, and it is the one probe here that can assert the refusal direction: after the cutover
# the auditor refuses to write, so its non-zero exit is a fact the environment must not be able to
# erase. It is FENCED rather than skipped — if the bats trees ever return, --write-manifest writes
# tests/parity-manifest.tsv, and a probe that quietly rewrote the evidence would be worse than no
# probe at all.
selfcheck_write_manifest() { # selfcheck_write_manifest <channel> <env command...>
  local channel="$1"
  shift
  if [ -d tests/unit ] || [ -d tests/acceptance ]; then
    selfcheck_fail "--write-manifest ($channel): the bats trees are present again, so this probe
          would REWRITE tests/parity-manifest.tsv. Rewrite the probe before running it; it must
          never touch the evidence."
    return 0
  fi
  selfcheck_probe "parity-audit.sh --write-manifest refuses ($channel)" refuse \
    'needs the bats trees' "$@" bash tools/parity-audit.sh --write-manifest
}

check_selfcheck() {
  step "selfcheck (the graders, under a hostile Go environment)"

  # The neutering program. /usr/bin/true where it exists (both CI images and this developer
  # platform have it); otherwise whatever `true` PATH resolves to. NEVER a silent skip: a
  # self-check that opts out on the machine it cannot arm is indistinguishable from one that
  # passed.
  local neuter=''
  if [ -x /usr/bin/true ]; then
    neuter='/usr/bin/true'
  else
    neuter="$(type -P true || true)"
  fi
  [ -n "$neuter" ] && [ -x "$neuter" ] || die "selfcheck: found no 'true' binary to build the neutering payload from"
  case "$neuter" in
    *[[:space:]]*) die "selfcheck: the path to 'true' ($neuter) contains whitespace, and GOFLAGS is
   split on spaces — the payload would not survive being written into it" ;;
  esac

  SELFCHECK_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/mctl-selfcheck.XXXXXX")"

  # Two flags, two different defeats: -exec replaces the grader with a program that grades
  # nothing, -ldflags rewrites the constant the parity auditor pins the corpus digest to. The
  # linker is silent about a -X that names a symbol a given program does not have, so the same
  # payload is safe to point at every one of these invocations.
  local payload="-exec=$neuter -ldflags=-X=main.manifestSHA256=$SELFCHECK_BOGUS_DIGEST"
  printf 'GOFLAGS=%s\n' "$payload" > "$SELFCHECK_TMPDIR/goenv"

  # THE SECOND PAYLOAD, FOR tests/smoke.sh, BECAUSE THE FIRST ONE CANNOT REACH IT. `go build` does
  # not honour -exec, and the manifest -X names a symbol the CLI does not have, so smoke's binary
  # would come out identical with or without the shared payload — its GOFLAGS and GOENV guards
  # would then sit there unprobed, which is the exact condition this whole stage exists to refuse.
  # What DOES reach it is the version stamp: an inherited
  # `-ldflags=-X=<version symbol>=<not a semver>` makes the self-built binary report something
  # --version's shape assertion refuses, so the smoke run answers a question about the shell rather
  # than about the CLI. It has to be a SEPARATE payload because GOFLAGS is split on spaces and one
  # -ldflags value cannot carry both -X settings.
  local vpayload="-ldflags=-X=$SELFCHECK_VERSION_SYMBOL=$SELFCHECK_BOGUS_VERSION"
  printf 'GOFLAGS=%s\n' "$vpayload" > "$SELFCHECK_TMPDIR/goenv-version"
  # Builds the CLI under whatever environment the probe hands it and prints its --version, so the
  # control can see whether the stamp actually landed.
  # shellcheck disable=SC2016  # $1 is the INNER bash -c's argument; expanding it here is the bug
  local vprobe='go build -o "$1/vprobe" ./cmd/mythical-ctl && "$1/vprobe" --version'

  # CHANNEL 1 — the GOFLAGS ENVIRONMENT VARIABLE.
  selfcheck_probe 'the payload neuters an unguarded go run (GOFLAGS variable)' neutered '' \
    env GOFLAGS="$payload" GOENV=off go run ./tools/boundary-gate
  selfcheck_probe 'boundary grader runs (GOFLAGS variable)' ok 'boundary-gate: clean' \
    env GOFLAGS="$payload" GOENV=off bash "$SELF" boundary
  selfcheck_probe 'parity grader runs (GOFLAGS variable)' ok 'parity-audit: every one of the' \
    env GOFLAGS="$payload" GOENV=off bash "$SELF" parity
  selfcheck_write_manifest 'GOFLAGS variable' env GOFLAGS="$payload" GOENV=off

  # tools/build-release.sh is the third script with graders in it, and its first `go run` decides
  # what the other steps operate on: neutered, `release-verify targets` prints nothing, the script
  # refuses an empty matrix, and the whole lane goes red for a reason that is not about the tree.
  # Its guard predates this stage; the probe is what keeps it. A plain build, not --repro — the
  # comparison is check.sh release's job, and this is asking a different question.
  selfcheck_probe 'release graders run (GOFLAGS variable)' ok 'all digests recomputed and matching' \
    env GOFLAGS="$payload" GOENV=off bash tools/build-release.sh 0.0.0-selfcheck "$SELFCHECK_TMPDIR/rel-goflags"
  selfcheck_probe 'the version payload reaches an unguarded go build (GOFLAGS variable)' ok \
    "$SELFCHECK_BOGUS_VERSION" \
    env GOFLAGS="$vpayload" GOENV=off bash -c "$vprobe" _ "$SELFCHECK_TMPDIR"
  selfcheck_probe 'smoke self-build reaches its true answer (GOFLAGS variable)' ok '0 failed' \
    env GOFLAGS="$vpayload" GOENV=off bash tests/smoke.sh

  # CHANNEL 2 — the go env FILE, and it is NOT the same channel. `GOFLAGS=''` does not close it:
  # go treats an EMPTY environment variable as UNSET and falls back to the file (measured — with
  # GOFLAGS='' exported and a file setting GOFLAGS, `go env GOFLAGS` reports the FILE's value). A
  # script that clears GOFLAGS without also setting GOENV=off is still wide open, and this channel
  # is the only thing that would say so.
  selfcheck_probe 'the payload neuters an unguarded go run (go env file)' neutered '' \
    env -u GOFLAGS GOENV="$SELFCHECK_TMPDIR/goenv" go run ./tools/boundary-gate
  selfcheck_probe 'boundary grader runs (go env file)' ok 'boundary-gate: clean' \
    env -u GOFLAGS GOENV="$SELFCHECK_TMPDIR/goenv" bash "$SELF" boundary
  selfcheck_probe 'parity grader runs (go env file)' ok 'parity-audit: every one of the' \
    env -u GOFLAGS GOENV="$SELFCHECK_TMPDIR/goenv" bash "$SELF" parity
  selfcheck_write_manifest 'go env file' env -u GOFLAGS GOENV="$SELFCHECK_TMPDIR/goenv"
  selfcheck_probe 'release graders run (go env file)' ok 'all digests recomputed and matching' \
    env -u GOFLAGS GOENV="$SELFCHECK_TMPDIR/goenv" bash tools/build-release.sh 0.0.0-selfcheck "$SELFCHECK_TMPDIR/rel-goenv"
  selfcheck_probe 'the version payload reaches an unguarded go build (go env file)' ok \
    "$SELFCHECK_BOGUS_VERSION" \
    env -u GOFLAGS GOENV="$SELFCHECK_TMPDIR/goenv-version" bash -c "$vprobe" _ "$SELFCHECK_TMPDIR"
  selfcheck_probe 'smoke self-build reaches its true answer (go env file)' ok '0 failed' \
    env -u GOFLAGS GOENV="$SELFCHECK_TMPDIR/goenv-version" bash tests/smoke.sh

  # CHANNEL 3 — an inherited go WORKSPACE. `go.work` is ambient file state of the same kind as the
  # go env file: the go command reads it without being asked, from GOWORK or from any ancestor
  # directory. Its effect here is the opposite sign and matters just as much — measured, a
  # workspace that does not `use` this directory makes `go list ./...` refuse outright, so every
  # stage would report a failure that says nothing whatever about this tree, which is the same
  # false answer the witness commands in tools/parity-audit.sh were guarded against in the first
  # place. Its `replace` directives also choose which copy of a dependency is compiled into a
  # grader. This is a single-module repository; there is no workspace here to honour.
  mkdir -p "$SELFCHECK_TMPDIR/other"
  printf 'module example.test/other\n\ngo 1.24.0\n' > "$SELFCHECK_TMPDIR/other/go.mod"
  printf 'package other\n' > "$SELFCHECK_TMPDIR/other/x.go"
  printf 'go 1.24.0\n\nuse ./other\n' > "$SELFCHECK_TMPDIR/go.work"
  selfcheck_probe 'the payload breaks an unguarded go command (go.work file)' breaks '' \
    env GOWORK="$SELFCHECK_TMPDIR/go.work" go list ./...
  selfcheck_probe 'boundary grader runs (go.work file)' ok 'boundary-gate: clean' \
    env GOWORK="$SELFCHECK_TMPDIR/go.work" bash "$SELF" boundary
  selfcheck_probe 'parity grader runs (go.work file)' ok 'parity-audit: every one of the' \
    env GOWORK="$SELFCHECK_TMPDIR/go.work" bash "$SELF" parity
  selfcheck_write_manifest 'go.work file' env GOWORK="$SELFCHECK_TMPDIR/go.work"
  selfcheck_probe 'release graders run (go.work file)' ok 'all digests recomputed and matching' \
    env GOWORK="$SELFCHECK_TMPDIR/go.work" bash tools/build-release.sh 0.0.0-selfcheck "$SELFCHECK_TMPDIR/rel-gowork"

  # And tests/smoke.sh's SELF-BUILD path, the one CI runs with MCTL_BIN deliberately absent so the
  # default stays proven. Only this channel can reach it: `go build` ignores -exec, and an
  # -ldflags version stamp still satisfies smoke's shape assertion, but a workspace that does not
  # `use` this directory stops the build outright.
  selfcheck_probe 'smoke self-build reaches its true answer (go.work file)' ok '0 failed' \
    env GOWORK="$SELFCHECK_TMPDIR/go.work" bash tests/smoke.sh

  [ "$SELFCHECK_RC" -eq 0 ] || die "a grader above can be switched off from the environment, so
   every stage that depends on it can report OK while the property it names is false."
  printf 'selfcheck: every grader ran and reported its own verdict under a hostile Go environment\n'
}

check_acceptance() {
  step "acceptance (real daemon)"
  go test -tags acceptance ./internal/engine/ -run 'TestAcceptance' -count=1 -v
}

check_go() {
  check_packages

  step "gofmt"
  local unformatted
  unformatted="$(gofmt -l .)"
  if [ -n "$unformatted" ]; then
    printf '%s\n' "$unformatted" >&2
    die "the files above are not gofmt-clean"
  fi

  step "go build"
  go build ./...

  step "go vet"
  go vet ./...

  check_boundary

  step "go test"
  # -count=1 defeats the test cache: a cached PASS is not evidence this commit passes.
  # UNFILTERED, and the Go environment is owned at the top of this file rather than here: an
  # inherited -run selection would satisfy the floor below while skipping nearly the whole suite.
  local out tested
  out="$(go test ./... -count=1 -json 2>&1)" || {
    printf '%s\n' "$out" | sed -n 's/.*"Output":"\(.*\)"}/\1/p' >&2
    printf '%s\n' "$out" >&2
    die "go test failed"
  }
  printf '%s\n' "$out" \
    | grep -aE '"Action":"(pass|fail|skip)"' \
    | grep -av '"Test":' \
    | sed -n 's/.*"Action":"\([a-z]*\)".*"Package":"\([^"]*\)".*/  \1  \2/p'
  tested="$(printf '%s\n' "$out" | count_ok)"
  assert_tested_floor "$tested"
}

case "${1:-all}" in
  packages) check_packages ;;
  boundary) check_boundary ;;
  go) check_go ;;
  parity) check_parity ;;
  release) check_release ;;
  acceptance) check_acceptance ;;
  selfcheck) check_selfcheck ;;
  # Reads `go test -json` output on stdin and applies the floor, so a harness can prove the
  # floor refuses; the `go` stage uses the same two functions.
  tested-floor) assert_tested_floor "$(count_ok)" ;;
  all)
    check_go
    check_parity
    check_selfcheck
    check_release
    ;;
  *) die "unknown stage: $1 (want one of: all, packages, boundary, go, parity, selfcheck, release, acceptance, tested-floor)" ;;
esac

printf '\ncheck.sh: OK\n'
