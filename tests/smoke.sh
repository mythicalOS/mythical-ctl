#!/usr/bin/env bash
# Smoke tests for the mythical-ctl entrypoint. No container runtime required —
# these cover the contract that packaging and release depend on.
#
# WHAT IT RUNS AGAINST. `MCTL_BIN` names a binary to test; that is how the
# release lane points it at the stamped artifact it is about to publish. With
# MCTL_BIN unset this script BUILDS one — `go build ./cmd/mythical-ctl` into a
# temporary directory — rather than falling back to a fixed path in the tree.
#
# The fallback used to be a fixed path in the tree, and every CI job passed
# MCTL_BIN, so the default was never exercised: it could have named anything at
# all and the lane would still be green. Building is the only default that
# cannot rot, and CI now runs this script ONCE WITH MCTL_BIN ABSENT precisely so
# the default stays proven.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

BUILT=''
# shellcheck disable=SC2317  # invoked via trap
cleanup() {
  if [ -n "$BUILT" ]; then
    rm -rf "$BUILT"
  fi
}
trap cleanup EXIT

if [ -n "${MCTL_BIN:-}" ]; then
  CTL="$MCTL_BIN"
else
  # A missing toolchain is a hard failure, never a skip. A smoke run that
  # quietly tested nothing would report the same "0 failed" as one that passed.
  command -v go > /dev/null 2>&1 || {
    printf 'smoke: MCTL_BIN is unset and there is no go toolchain to build one with\n' >&2
    exit 1
  }
  BUILT="$(mktemp -d "${TMPDIR:-/tmp}/mctl-smoke.XXXXXX")"
  CTL="$BUILT/mythical-ctl"
  ( cd "$ROOT" && go build -o "$CTL" ./cmd/mythical-ctl ) || {
    printf 'smoke: could not build the CLI to test\n' >&2
    exit 1
  }
fi

pass=0
fail=0

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  ok    %s\n' "$name"; pass=$((pass + 1))
  else
    printf '  FAIL  %s\n' "$name"; fail=$((fail + 1))
  fi
}

check_eq() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    printf '  ok    %s\n' "$name"; pass=$((pass + 1))
  else
    printf '  FAIL  %s (expected %q, got %q)\n' "$name" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

# Exits non-zero on failure, so `check` needs the inverted form for these.
check_exit_code() {
  local name="$1" expected="$2"; shift 2
  local actual=0
  "$@" >/dev/null 2>&1 || actual=$?
  check_eq "$name" "$expected" "$actual"
}

printf 'mythical-ctl smoke\n'
printf 'binary under test: %s\n' "$CTL"

check      'is executable'                    test -x "$CTL"
check_exit_code 'no args exits 0 (prints help)' 0 "$CTL"
check_exit_code '--help exits 0'                0 "$CTL" --help
check_exit_code '--version exits 0'             0 "$CTL" --version
# 2 distinguishes a usage error from an operational failure (1). Callers and CI
# rely on that split, so it is pinned here rather than left to convention.
check_exit_code 'unknown command exits 2'       2 "$CTL" not-a-real-command

# The release workflow asserts the git tag equals this version, so the format
# has to stay machine-readable: exactly "mythical-ctl <semver>". The prerelease
# suffix is PERMITTED, not merely tolerated: the tag grammar the release
# workflow accepts is vX.Y.Z[-suffix], and an unstamped development build
# reports X.Y.Z-dev — so a shape that rejected a suffix would fail on every
# binary except a final release, which is the one this script least needs to be
# able to run against.
version_line="$("$CTL" --version)"
if printf '%s' "$version_line" | grep -qE '^mythical-ctl [0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  printf '  ok    --version format is "mythical-ctl <semver>"\n'; pass=$((pass + 1))
else
  printf '  FAIL  --version format: %q\n' "$version_line"; fail=$((fail + 1))
fi

# `-v` is --version's TWIN, not a near-synonym: same exit status, byte-identical
# output. It is the short form people actually type, and a divergence in it is
# invisible to every other check in this file.
v_short_rc=0
v_short="$("$CTL" -v)" || v_short_rc=$?
if [ "$v_short_rc" -eq 0 ] && [ "$v_short" = "$version_line" ]; then
  printf "  ok    -v is --version's twin\n"; pass=$((pass + 1))
else
  printf '  FAIL  -v: rc=%d output=%q (--version gave %q)\n' "$v_short_rc" "$v_short" "$version_line"
  fail=$((fail + 1))
fi

# Usage errors must not pollute stdout — a caller parsing --version output
# should never receive an error message on the same stream.
if [ -z "$("$CTL" not-a-real-command 2>/dev/null || true)" ]; then
  printf '  ok    usage errors go to stderr, not stdout\n'; pass=$((pass + 1))
else
  printf '  FAIL  usage error leaked to stdout\n'; fail=$((fail + 1))
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
