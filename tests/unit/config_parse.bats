#!/usr/bin/env bats
load '../lib/test_helper'

setup() { setup_test_env; load_mctl; }   # setup_test_env FIRST: bats does not chain setup()

# The load-bearing test: a value that WOULD execute if the file were sourced.
# Two independent assertions — nothing ran, AND the line was refused.
@test "a command substitution never executes and is refused" {
  local f="$MYTHICAL_HOME/hostile.conf" sentinel="$MYTHICAL_HOME/PWNED"
  printf 'MYTHICAL_X=$(touch %s)\n' "$sentinel" > "$f"
  run mi_conf_scan "$f"
  [ "$status" -eq 1 ]
  [ ! -e "$sentinel" ]
}

@test "a backtick substitution never executes and is refused" {
  local f="$MYTHICAL_HOME/hostile.conf" sentinel="$MYTHICAL_HOME/PWNED"
  printf 'MYTHICAL_X=`touch %s`\n' "$sentinel" > "$f"
  run mi_conf_scan "$f"
  [ "$status" -eq 1 ]
  [ ! -e "$sentinel" ]
}

@test "a NUL byte is detected — which a variable-based check cannot do" {
  local f="$MYTHICAL_HOME/nul.conf"
  printf 'MYTHICAL_X=a\000b\n' > "$f"
  run mi_conf_scan "$f"
  [ "$status" -eq 1 ]
}

@test "CR, TAB and other control bytes are refused" {
  local f="$MYTHICAL_HOME/c.conf" b
  for b in '\r' '\t' '\013' '\177'; do
    printf "MYTHICAL_X=a${b}b\n" > "$f"
    run mi_conf_scan "$f"
    [ "$status" -eq 1 ] || { echo "byte ${b} was accepted" >&2; return 1; }
  done
}

@test "a plain KEY=value file parses to tab-delimited records" {
  local f="$MYTHICAL_HOME/ok.conf"
  printf '# a comment\n\nMYTHICAL_NET=mythical-net\nMYTHICAL_TELEMETRY_KEY=abc123\n' > "$f"
  run mi_conf_scan "$f"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "$(printf 'MYTHICAL_NET\tmythical-net')" ]
  [ "${lines[1]}" = "$(printf 'MYTHICAL_TELEMETRY_KEY\tabc123')" ]
  [ "${#lines[@]}" -eq 2 ]
}

@test "a value keeps its = signs — only the FIRST separates" {
  local f="$MYTHICAL_HOME/eq.conf"
  printf 'MYTHICAL_X=a=b=c\n' > "$f"
  run mi_conf_scan "$f"
  [ "$status" -eq 0 ]
  [ "$output" = "$(printf 'MYTHICAL_X\ta=b=c')" ]
}

@test "a non-ASCII value is accepted — refusing UTF-8 would break real home directories" {
  local f="$MYTHICAL_HOME/utf.conf"
  printf 'MYTHICAL_X=/Users/Jos\xc3\xa9/work\n' > "$f"
  run mi_conf_scan "$f"
  [ "$status" -eq 0 ]
}

@test "shell metacharacters in a value are refused" {
  local f="$MYTHICAL_HOME/meta.conf" c
  for c in '$' '`' '\'; do
    printf 'MYTHICAL_X=a%sb\n' "$c" > "$f"
    run mi_conf_scan "$f"
    [ "$status" -eq 1 ] || { echo "metachar ${c} was accepted" >&2; return 1; }
  done
}

@test "a key outside the MYTHICAL_ namespace is refused" {
  printf 'PATH=/evil\n' > "$MYTHICAL_HOME/k.conf"
  run mi_conf_scan "$MYTHICAL_HOME/k.conf"
  [ "$status" -eq 1 ]
}

@test "a lowercase or punctuated key is refused" {
  local f="$MYTHICAL_HOME/k.conf" k
  for k in 'mythical_x' 'MYTHICAL_x' 'MYTHICAL_X-Y' 'MYTHICAL_X.Y' 'MYTHICAL_'; do
    printf '%s=1\n' "$k" > "$f"
    run mi_conf_scan "$f"
    [ "$status" -eq 1 ] || { echo "key ${k} was accepted" >&2; return 1; }
  done
}

@test "a line with no = is refused rather than skipped" {
  printf 'MYTHICAL_NET\n' > "$MYTHICAL_HOME/k.conf"
  run mi_conf_scan "$MYTHICAL_HOME/k.conf"
  [ "$status" -eq 1 ]
}

@test "a duplicate key is refused as ambiguous" {
  printf 'MYTHICAL_NET=a\nMYTHICAL_NET=b\n' > "$MYTHICAL_HOME/k.conf"
  run mi_conf_scan "$MYTHICAL_HOME/k.conf"
  [ "$status" -eq 1 ]
}

@test "a file without a trailing newline is refused as truncated" {
  printf 'MYTHICAL_NET=a' > "$MYTHICAL_HOME/k.conf"
  run mi_conf_scan "$MYTHICAL_HOME/k.conf"
  [ "$status" -eq 1 ]
}

@test "leading or trailing space in a value is refused" {
  local f="$MYTHICAL_HOME/s.conf"
  printf 'MYTHICAL_X= a\n' > "$f"; run mi_conf_scan "$f"; [ "$status" -eq 1 ]
  printf 'MYTHICAL_X=a \n' > "$f"; run mi_conf_scan "$f"; [ "$status" -eq 1 ]
}

@test "an interior space is accepted — bind paths contain them" {
  printf 'MYTHICAL_X=/Users/me/My Projects\n' > "$MYTHICAL_HOME/s.conf"
  run mi_conf_scan "$MYTHICAL_HOME/s.conf"
  [ "$status" -eq 0 ]
}

@test "an empty value is accepted" {
  printf 'MYTHICAL_X=\n' > "$MYTHICAL_HOME/e.conf"
  run mi_conf_scan "$MYTHICAL_HOME/e.conf"
  [ "$status" -eq 0 ]
  [ "$output" = "$(printf 'MYTHICAL_X\t')" ]
}

@test "an empty file parses to nothing, successfully" {
  : > "$MYTHICAL_HOME/e.conf"
  run mi_conf_scan "$MYTHICAL_HOME/e.conf"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

# Every public function must refuse a malformed call in its own words rather than aborting the CLI
# with bash's "unbound variable" under the entrypoint's `set -u`.
@test "the public readers refuse bad arity instead of aborting under set -u" {
  local call
  for call in 'mi_conf_scan' 'mi_conf_load "$MYTHICAL_HOME/x"' 'mi_conf_get "$MYTHICAL_HOME/x"'; do
    run bash -c 'set -euo pipefail
      for m in common layout config lock ledger; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
      '"$call"'; echo UNREACHABLE'
    [ "$status" -ne 0 ] || { echo "no refusal for: $call" >&2; return 1; }
    [[ "$output" != *UNREACHABLE* ]] || { echo "continued after: $call" >&2; return 1; }
    [[ "$output" != *"unbound variable"* ]] || { echo "aborted on unbound for: $call" >&2; return 1; }
  done
}

@test "a missing file reports rc 3, distinct from malformed" {
  run mi_conf_scan "$MYTHICAL_HOME/nope.conf"
  [ "$status" -eq 3 ]
}
