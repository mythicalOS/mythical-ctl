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
# THE RULE enforced below: a `[[ … ]]` in COMMAND position — at the start of a statement, or after a
# `;` — must carry a `||` fallback, UNLESS it is the last command the body executes. A `[[ ]]` opening
# an `if`/`while`/`until`/`elif` is a condition rather than an assertion and is exempt.
#
# "Last command the body executes" is deliberately not "last line": a body ending in
# `true; [[ f ]]; true` ends with `true`, so the assertion decides nothing.
#
# It is a heuristic, and its boundary is stated rather than hidden: it accepts `[[ a ]] && [[ b ]] || c`,
# which would also not fail. What it must not be is silently narrower than it reads, and it was — three
# times. An early version matched only a line ENDING in `]]`, so `[[ f ]]; true` and `[[ f ]] && true`
# sailed through. Then it joined comment-tailed backslashes as continuations, importing a `||` from the
# following statement. Then it exempted a whole final LINE rather than the final command. Each of those
# reported a clean suite while missing a real decorative assertion.
#
# Which is why the first test exists: the detector is run against a fixture with known answers, so it
# cannot report clean on the real suites without first proving it catches all eight shapes.

# Emit "file:line: statement" for every unguarded `[[ … ]]` assertion in the given .bats files.
# Continuation lines are joined first: `[[ … ]] \` + `|| { … }` is CORRECT, and a scanner that judged
# the first physical line alone would report it as a defect.
_scan_bats() {
  awk '
    # A body is flattened into an ordered list of SEGMENTS — `;`-separated commands — rather than a
    # list of lines. Two reasons, both from real false negatives:
    #
    #   `true; [[ f ]]; true`  is one line and does not START with `[[`, so a line-level test misses
    #                          the assertion buried in the middle of it.
    #   the "last one is exempt" rule has to mean the last SEGMENT EXECUTED IN THE BODY, not the last
    #                          line. A body whose final line is `true; [[ f ]]; true` ends with
    #                          `true`, so the assertion is not the deciding command and is decorative.
    #                          Exempting it because its LINE was last is exactly the miss that got
    #                          through round 5.
    function flush_stmt(   j, m, semis, seg, k, q, parts, part, cond) {
      if (pending == "") return
      m = split(pending, semis, ";")
      for (j = 1; j <= m; j++) {
        seg = semis[j]
        sub(/^[ \t]+/, "", seg); sub(/[ \t]+$/, "", seg)
        if (seg == "") continue
        # Does this `;`-segment OPEN a compound condition? If so, every `&&` part of it is condition
        # context, not an assertion — `if [[ a ]] && [[ b ]]; then` must not report `[[ b ]]`.
        cond = (seg ~ /^(if|while|until|elif|!)[ \t]/)
        # Split on `&&` too: in `true && [[ f ]] && true` the assertion is an INTERMEDIATE command of
        # an and-list, so errexit does not stop the body and the trailing `true` carries the status.
        # A `;`-level split alone sees one segment beginning with `true` and never looks inside it.
        q = split(seg, parts, "&&")
        for (k = 1; k <= q; k++) {
          part = parts[k]
          sub(/^[ \t]+/, "", part); sub(/[ \t]+$/, "", part)
          if (part == "") continue
          sn++; sseg[sn] = part; sln[sn] = pending_ln; sfull[sn] = pending; scond[sn] = cond
        }
      }
      pending = ""
    }
    /^@test /     { inb = 1; sn = 0; pending = ""; bodies++; next }
    inb && /^\}/  {
                    flush_stmt()
                    # `i < sn`: only the FINAL segment of the whole body is exempt, because that is the
                    # one whose status bats takes as the result.
                    for (i = 1; i < sn; i++) {
                      if (scond[i]) continue                                # inside an if/while condition
                      if (sseg[i] ~ /\|\|/) continue                         # has a fallback: it fails
                      if (sseg[i] ~ /^(if|while|until|elif|!)[ \t]/) continue  # a condition, not an assertion
                      if (sseg[i] ~ /^\[\[/) printf "%s:%d: %s\n", FILENAME, sln[i], sfull[i]
                    }
                    inb = 0; next
                  }
    inb           {
                    line = $0
                    sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                    if (line == "" || line ~ /^#/) next
                    if (pending == "") pending_ln = FNR
                    # A trailing backslash continues the statement — UNLESS it is inside a trailing
                    # comment, where bash ignores it. `[[ f ]] # note \` and `[[ f ]];# note \` do NOT
                    # continue, so joining either with the next line would import a `||` from a
                    # statement that is not part of this one and wave a decorative assertion through.
                    # A `#` starts a comment at line start or after whitespace or an operator, which is
                    # what the class below approximates. It is a heuristic — a `#` inside quotes could
                    # trip it — but it errs toward a FALSE POSITIVE, a visible and fixable complaint,
                    # rather than a silent miss.
                    if (line ~ /\\$/ && line !~ /[ \t;&|(]#/) {
                      sub(/\\$/, "", line); pending = pending line " "; next
                    }
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
    printf '%s\n' '@test "bad 4: embedded after a semicolon" {' "  true; $A; true" '  true' '}'
    printf '%s\n' '@test "bad 5: comment-tailed pseudo-continuation" {' "  $A # explanation \\" \
                  '  true || :' '  true' '}'
    printf '%s\n' '@test "bad 6: compound LAST line, assertion is not the deciding command" {' \
                  "  true; $A; true" '}'
    printf '%s\n' '@test "bad 7: semicolon-hash pseudo-continuation" {' "  $A;# explanation \\" \
                  '  true || :' '  true' '}'
    printf '%s\n' '@test "bad 8: intermediate command of an and-list" {' "  true && $A && true" '  true' '}'
    printf '%s\n' '@test "good 5: and-list whose condition really is a condition" {' \
                  "  if $A && $A; then true; fi" '  true' '}'
    printf '%s\n' '@test "good 1: guarded" {' "  $A || { echo boom >&2; return 1; }" '  true' '}'
    printf '%s\n' '@test "good 2: guarded across a continuation" {' "  $A \\" \
                  '    || { echo boom >&2; return 1; }' '  true' '}'
    printf '%s\n' '@test "good 3: a condition, not an assertion" {' "  if $A; then true; fi" '  true' '}'
    printf '%s\n' '@test "good 4: last statement, so bats takes its status" {' '  true' "  $A" '}'
  } > "$fx"

  out="$(_scan_bats "$fx")"

  found="$(printf '%s\n' "$out" | grep -c . )"
  [ "$found" -eq 8 ] \
    || { echo "expected exactly 8 findings, got $found:" >&2; echo "$out" >&2; return 1; }
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
  [ "$(_bodies_seen)" -eq 13 ] \
    || { echo "the scanner saw $(_bodies_seen) bodies in a 13-test fixture" >&2; return 1; }
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
