#!/usr/bin/env bats
# Hygiene of the test suites themselves. A test that cannot fail is worse than a missing test: it
# reports coverage it does not provide, and it does so silently.
load '../lib/test_helper'

setup() { setup_test_env; }

# THE TRAP, measured on this repository's version floor (/bin/bash 3.2.57, which is what bats runs
# under here, and what macOS ships). Errexit does not fire on `[[ ]]`, so every one of these PASSES:
#
#   @test "…" { [[ "a" == "b" ]]; true; }        ok   — decorative
#   @test "…" { [[ "a" == "b" ]] && true; true; } ok   — decorative
#   @test "…" { [[ "a" == "b" ]]                 ok   — decorative
#              true; }
#
# while the same assertion with `[ ]` fails correctly, and a `[[ ]]` that happens to be the LAST
# command in the body fails only because bats takes the body's final status.
#
# Bash 5 (Linux, and therefore CI) DOES apply errexit to `[[ ]]`, so such an assertion is live there
# and dead here — the suite is stricter in CI than on the floor it claims to support, and a
# developer's green run is not evidence. Fourteen of these existed when this guard was written; all
# fourteen happened to be true, which was luck, not design.
#
# The form that fails identically on 3.2 and 5, and says what went wrong:
#
#   [[ "$output" == *needle* ]] || { echo "no needle in: $output" >&2; return 1; }
#
# So the rule enforced below is: a statement that STARTS with `[[` must carry a `||` fallback, unless
# it is the last statement of its body. That is a heuristic, deliberately — it accepts
# `[[ … ]] || echo` which would also not fail — but it catches every shape observed in practice, and
# the first test proves the detector actually catches them rather than merely reporting clean.

# Emit "file:line: statement" for every unguarded `[[ … ]]` assertion in the given .bats files.
# Continuation lines are joined first: `[[ … ]] \` + `|| { … }` is CORRECT, and a scanner that judged
# the first physical line alone would report it as a defect.
_scan_bats() {
  awk '
    function flush_stmt() {
      if (pending == "") return
      n++; stmt[n] = pending; ln[n] = pending_ln; pending = ""
    }
    /^@test /     { inb = 1; n = 0; pending = ""; bodies++; next }
    inb && /^\}/  {
                    flush_stmt()
                    for (i = 1; i < n; i++)
                      if (stmt[i] ~ /^\[\[/ && stmt[i] !~ /\|\|/)
                        printf "%s:%d: %s\n", FILENAME, ln[i], stmt[i]
                    inb = 0; next
                  }
    inb           {
                    line = $0
                    sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                    if (line == "" || line ~ /^#/) next
                    if (pending == "") pending_ln = FNR
                    # a trailing backslash continues the statement onto the next line
                    if (line ~ /\\$/) { sub(/\\$/, "", line); pending = pending line " "; next }
                    pending = pending line
                    flush_stmt()
                  }
    END           { print "BODIES=" bodies > "/dev/stderr" }
  ' "$@" 2>"$MYTHICAL_HOME/bodies"
}

_bodies_seen() { sed -n 's/^BODIES=//p' "$MYTHICAL_HOME/bodies"; }

# The detector's own correctness, tested against a fixture with known answers. Without this, the guard
# could only ever report "clean" — and a scanner whose pattern stops matching reports clean for every
# input, which is indistinguishable from a healthy suite and is the exact failure mode this file
# exists to catch. Two of the bad shapes below were missed by an earlier version of this scanner.
@test "the scanner finds every decorative shape, and none of the sound ones" {
  local fx="$MYTHICAL_HOME/fixture.bats" out found

  # The fixture is ASSEMBLED, not written as a heredoc, and both reasons are load-bearing:
  #
  #   1. bats splits a test file on `@test` at column 0. A heredoc containing `@test` lines is
  #      therefore torn apart by bats' own preprocessing — the enclosing test body ends at the first
  #      embedded line and the fixture's tests are collected as REAL ones. Observed: this test
  #      silently scanned nothing while the guard below reported the fixture's contents as defects in
  #      this very file.
  #   2. A literal `[[ … ]]` at the start of a line here would be a genuine finding in this file,
  #      because the scanner cannot know it is fixture data either.
  #
  # Keeping the bad shapes inside `printf` arguments avoids both.
  local A='[[ "a" == "b" ]]'
  { printf '%s\n' '@test "bad 1: bare, mid-body" {' "  $A" '  true' '}'
    printf '%s\n' '@test "bad 2: semicolon-chained" {' "  $A; true" '  true' '}'
    printf '%s\n' '@test "bad 3: and-chained" {' "  $A && true" '  true' '}'
    printf '%s\n' '@test "good 1: guarded" {' "  $A || { echo boom >&2; return 1; }" '  true' '}'
    printf '%s\n' '@test "good 2: guarded across a continuation" {' "  $A \\" \
                  '    || { echo boom >&2; return 1; }' '  true' '}'
    printf '%s\n' '@test "good 3: a condition, not an assertion" {' "  if $A; then true; fi" '  true' '}'
    printf '%s\n' '@test "good 4: last statement, so bats takes its status" {' '  true' "  $A" '}'
  } > "$fx"

  out="$(_scan_bats "$fx")"

  found="$(printf '%s\n' "$out" | grep -c . )"
  [ "$found" -eq 3 ] \
    || { echo "expected exactly 3 findings, got $found:" >&2; echo "$out" >&2; return 1; }
  case "$out" in
    *'== "b" ]]'*) : ;;
    *) echo "findings do not name the offending statement: $out" >&2; return 1 ;;
  esac
  case "$out" in
    *'|| { echo boom'*) echo "the scanner flagged a GUARDED assertion: $out" >&2; return 1 ;;
  esac
  case "$out" in
    *'if [['*) echo "the scanner flagged a condition, not an assertion: $out" >&2; return 1 ;;
  esac
  [ "$(_bodies_seen)" -eq 7 ] \
    || { echo "the scanner saw $(_bodies_seen) bodies in a 7-test fixture" >&2; return 1; }
}

@test "no test asserts with a bare [[ ]] that bash 3.2 cannot fail on" {
  local out bodies
  out="$(_scan_bats "${_MCTL_ROOT}"/tests/unit/*.bats)"

  # Self-check FIRST, so this cannot pass by having scanned nothing.
  bodies="$(_bodies_seen)"
  case "$bodies" in
    ''|*[!0-9]*) echo "the scanner reported no body count — it did not run" >&2; return 1 ;;
  esac
  if [ "$bodies" -lt 50 ]; then
    echo "the scanner found only $bodies test bodies — it is not matching, so this guard is vacuous" >&2
    return 1
  fi

  if [ -n "$out" ]; then
    echo "assertions that cannot fail on bash 3.2 (use the '|| { echo …; return 1; }' form):" >&2
    echo "$out" >&2
    return 1
  fi
}
