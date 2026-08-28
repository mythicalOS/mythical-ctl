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

# A scratch directory ALWAYS, not only when self-building: the version assertions
# below capture output to FILES and compare the bytes, which a shell variable
# cannot do (command substitution strips trailing newlines, so two outputs that
# differ only there compare equal).
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mctl-smoke.XXXXXX")"
# shellcheck disable=SC2317  # invoked via trap
cleanup() { rm -rf "$WORK"; }
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
  CTL="$WORK/mythical-ctl"
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

# The release workflow asserts the git tag equals this version, so the format has
# to stay machine-readable: exactly "mythical-ctl <semver>", on stdout, ONE line,
# terminated. The prerelease suffix is PERMITTED, not merely tolerated: the tag
# grammar the release workflow accepts is vX.Y.Z[-suffix], and an unstamped
# development build reports X.Y.Z-dev — so a shape that rejected a suffix would
# fail on every binary except a final release, which is the one this script least
# needs to be able to run against.
#
# THE WHOLE OF STDOUT IS THE ASSERTION, not "a line of it somewhere". `grep -E`
# with anchors matches a LINE, so `junk\nmythical-ctl 1.2.3\n` satisfies the
# pattern while being nothing a caller could parse — and counting NEWLINES does
# not fix it either, because `mythical-ctl 1.2.3\nTRAILING-JUNK` has exactly one
# newline and two records. So the capture is required to equal its own first line
# plus a terminator, byte for byte: that is one record, terminated, and nothing
# else on the stream. Then the shape is asked of that line.
#
# The redirect is rc-guarded. Under `set -e` an unguarded one aborts the script
# on a binary whose --version fails, which truncates the report and drops the
# summary — a run that tested less than it says, in silence.
version_rc=0
"$CTL" --version > "$WORK/version.out" 2> "$WORK/version.err" || version_rc=$?
version_line="$(head -n 1 "$WORK/version.out")"
printf '%s\n' "$version_line" > "$WORK/version.want"
if [ "$version_rc" -eq 0 ] && cmp -s "$WORK/version.out" "$WORK/version.want" \
  && printf '%s' "$version_line" | grep -qE '^mythical-ctl [0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  printf '  ok    --version is exactly one line, "mythical-ctl <semver>"\n'; pass=$((pass + 1))
else
  printf '  FAIL  --version: rc=%d, stdout %q\n' "$version_rc" "$(cat "$WORK/version.out")"
  fail=$((fail + 1))
fi

# `-v` is --version's TWIN: same exit status, and the same BYTES ON BOTH STREAMS
# — compared with cmp on captured files, not with `[ "$a" = "$b" ]` on two
# command substitutions. Command substitution strips every trailing newline, so
# the variable form calls two outputs identical when one ends in a blank line the
# other does not have; and it cannot hold a NUL at all. STDERR IS COMPARED TOO,
# not discarded: in the frozen reference these were one `case` branch, so a
# warning that appears on one and not the other is a divergence, and discarding
# the stream is how it would go unseen. It is the short form people actually
# type, and a difference in it is invisible to every other check in this file.
v_short_rc=0
"$CTL" -v > "$WORK/v.out" 2> "$WORK/v.err" || v_short_rc=$?
v_diff=''
cmp -s "$WORK/v.out" "$WORK/version.out" || v_diff="stdout"
cmp -s "$WORK/v.err" "$WORK/version.err" || v_diff="${v_diff:+$v_diff and }stderr"
if [ "$v_short_rc" -eq 0 ] && [ -z "$v_diff" ]; then
  printf "  ok    -v is --version's twin, byte for byte on both streams\n"; pass=$((pass + 1))
else
  printf '  FAIL  -v: rc=%d, differs on %s (stdout %q, stderr %q; --version gave %q / %q)\n' \
    "$v_short_rc" "${v_diff:-the exit status alone}" "$(cat "$WORK/v.out")" "$(cat "$WORK/v.err")" \
    "$version_line" "$(cat "$WORK/version.err")"
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
