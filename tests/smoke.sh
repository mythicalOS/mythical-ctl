#!/usr/bin/env bash
# Smoke tests for the mythical-ctl entrypoint. No container runtime required —
# these cover the contract that packaging and release depend on.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTL="$HERE/../bin/mythical-ctl"

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

check      'is executable'                    test -x "$CTL"
check_exit_code 'no args exits 0 (prints help)' 0 "$CTL"
check_exit_code '--help exits 0'                0 "$CTL" --help
check_exit_code '--version exits 0'             0 "$CTL" --version
# 2 distinguishes a usage error from an operational failure (1). Callers and CI
# rely on that split, so it is pinned here rather than left to convention.
check_exit_code 'unknown command exits 2'       2 "$CTL" not-a-real-command

# The release workflow asserts the git tag equals this version, so the format
# has to stay machine-readable: exactly "mythical-ctl <semver>".
version_line="$("$CTL" --version)"
if printf '%s' "$version_line" | grep -qE '^mythical-ctl [0-9]+\.[0-9]+\.[0-9]+$'; then
  printf '  ok    --version format is "mythical-ctl <semver>"\n'; pass=$((pass + 1))
else
  printf '  FAIL  --version format: %q\n' "$version_line"; fail=$((fail + 1))
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
