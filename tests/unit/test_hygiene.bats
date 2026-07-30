#!/usr/bin/env bats
# Hygiene of the test suites themselves. A test that cannot fail is worse than a missing test: it
# reports coverage it does not provide, and it does so silently.
load '../lib/test_helper'

setup() { setup_test_env; }

# THE TRAP, measured on this repository's version floor (/bin/bash 3.2.57, which is what bats runs
# under here, and what macOS ships):
#
#   @test "…" { [[ "a" == "b" ]]; true; }   →  ok       PASSES — errexit does not fire on [[ ]]
#   @test "…" { [ "a" = "b" ];   true; }   →  not ok   fails correctly
#   @test "…" { [[ "a" == "b" ]]; }        →  not ok   fails, but only because it is the LAST command
#
# So a standalone `[[ … ]]` that is not the final statement of its test body asserts NOTHING on bash
# 3.2: execution continues and only the last command decides pass/fail. Bash 5 (Linux, and therefore
# CI) does apply errexit to `[[ ]]`, so such an assertion is live there and dead here — the suite is
# stricter in CI than on the floor it claims to support, and a developer's green run is not evidence.
#
# Fourteen of these existed when this guard was written. All fourteen turned out to be TRUE, so
# nothing was being hidden — but that was luck, not design, and it was invisible either way.
#
# The fix is the explicit form, which fails identically on 3.2 and 5 and says what went wrong:
#
#   [[ "$output" == *needle* ]] || { echo "no needle in: $output" >&2; return 1; }
#
# A `[[ … ]]` used as a CONDITION — inside `if`/`while`, or as the left side of `||`/`&&` — is
# correct as it stands and is not reported.
@test "no test asserts with a bare [[ ]] that bash 3.2 cannot fail on" {
  local out bodies
  # `stmt`/`ln` are overwritten rather than deleted between bodies and only indices 1..n are read:
  # `delete arr` (whole-array) is not POSIX awk and BSD awk has not always had it.
  out="$(awk '
    /^@test /     { inb = 1; n = 0; bodies++; next }
    inb && /^\}/  {
                    for (i = 1; i < n; i++)
                      if (stmt[i] ~ /^\[\[.*\]\]$/)
                        printf "%s:%d: %s\n", FILENAME, ln[i], stmt[i]
                    inb = 0; next
                  }
    inb           {
                    line = $0
                    sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                    if (line == "" || line ~ /^#/) next
                    n++; stmt[n] = line; ln[n] = FNR
                  }
    END           { print "BODIES=" bodies > "/dev/stderr" }
  ' "${_MCTL_ROOT}"/tests/unit/*.bats 2>"$MYTHICAL_HOME/bodies")"

  # Self-check FIRST, so this guard cannot pass by having scanned nothing. A scanner whose pattern
  # stops matching reports zero findings, which is indistinguishable from a clean suite — the same
  # failure mode the guard exists to catch. Every suite in this directory has test bodies, so a
  # count in the low hundreds is the only healthy answer.
  bodies="$(sed -n 's/^BODIES=//p' "$MYTHICAL_HOME/bodies")"
  case "$bodies" in
    ''|*[!0-9]*) echo "the scanner reported no body count — it did not run" >&2; return 1 ;;
  esac
  if [ "$bodies" -lt 50 ]; then
    echo "the scanner found only $bodies test bodies — it is not matching, so this guard is vacuous" >&2
    return 1
  fi

  if [ -n "$out" ]; then
    echo "bare [[ ]] assertions that cannot fail on bash 3.2 (use the '|| { echo …; return 1; }' form):" >&2
    echo "$out" >&2
    return 1
  fi
}
