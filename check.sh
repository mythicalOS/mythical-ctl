#!/usr/bin/env bash
#
# check.sh — every check the Go tree gets, in one place.
#
#   bash check.sh            # everything CI runs for the Go lane
#   bash check.sh packages   # only the "does this lane actually cover anything" guard
#   bash check.sh go         # packages + gofmt + build + vet + boundary + test
#   bash check.sh boundary   # only the reference-boundary gates
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

# Floors, not exact counts: the tree grows a package per port task, and each task raises these
# two literals in its commit. Overridable ONLY so a test harness can prove the guard refuses.
MIN_PACKAGES="${MIN_PACKAGES:-8}"
MIN_TESTED_PACKAGES="${MIN_TESTED_PACKAGES:-8}"

# The reference-boundary rules, one per line: `<guarded-import-path>:<Identifier>=<allowed
# import path>[,<more allowed>]`. The defining package itself is always allowed. Each rule is
# added by the task that creates the boundary and NEVER removed — these survive the bash
# cutover; a once-run audit protects nothing afterwards. The gate resolves REFERENCES via the
# AST (selector and identifier use, not call syntax), so a function VALUE of a guarded symbol
# is caught too — see tools/boundary-gate.
BOUNDARY_RULES=(
  # staging-boundary (Task 8): the restore staging store is constructed ONLY by the backup
  # module — a lifecycle path that could open staging would treat a not-yet-verified restore
  # as live state.
  "mythicalos.ai/ctl/internal/ledger:OpenStaging=mythicalos.ai/ctl/internal/backup"
)

die() {
  printf 'check.sh: ERROR: %s\n' "$*" >&2
  exit 1
}
step() { printf '\n=== %s ===\n' "$*"; }

check_packages() {
  step "packages"
  command -v go > /dev/null 2>&1 || die "no go toolchain on PATH"
  go version
  local listed count
  listed="$(go list ./...)"
  count="$(printf '%s\n' "$listed" | awk 'NF {n++} END {print n + 0}')"
  printf '%s\n' "$listed"
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
  go run ./tools/boundary-gate "${BOUNDARY_RULES[@]}"
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
  # UNFILTERED, with GOFLAGS/GOENV owned by the invocation: an inherited -run selection would
  # satisfy the floor below while skipping nearly the whole suite.
  local out tested
  out="$(GOFLAGS='' GOENV=off go test ./... -count=1 -json 2>&1)" || {
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
  # Reads `go test -json` output on stdin and applies the floor, so a harness can prove the
  # floor refuses; the `go` stage uses the same two functions.
  tested-floor) assert_tested_floor "$(count_ok)" ;;
  all) check_go ;;
  *) die "unknown stage: $1 (want one of: all, packages, boundary, go, tested-floor)" ;;
esac

printf '\ncheck.sh: OK\n'
