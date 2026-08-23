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

# --- the key-count cap ----------------------------------------------------------------------------
# The duplicate check below scans a `seen` string that grows one entry per key, so it is QUADRATIC —
# and the whole-file size ceiling bounds the BYTES copied, not the work done. Measured on this code
# path with the cap lifted: 4000 keys 2s, 8000 7s, 14000 22s (240 KB), 20000 46s (349 KB). Every one
# of those files is comfortably inside the accepted 1 MiB ceiling, and mi_conf_product_add runs the
# scan while HOLDING the family lock — so one compromised container could wedge every other product's
# mutating operation for minutes. MI_CONF_MAXKEYS bounds it.
#
# awk builds the fixtures: an append loop of this length costs seconds under bats' per-command DEBUG
# trap, for no benefit.
many_keys() { awk -v n="$1" 'BEGIN{for(i=0;i<n;i++)printf "MYTHICAL_K%d=v\n", i}' > "$2"; }

@test "the key-count cap is exact: 1024 keys accepted, 1025 refused" {
  local f="$MYTHICAL_HOME/many.conf"
  [ "$MI_CONF_MAXKEYS" -eq 1024 ]
  many_keys 1024 "$f"
  run mi_conf_scan "$f"
  [ "$status" -eq 0 ]
  [ "${#lines[@]}" -eq 1024 ]
  many_keys 1025 "$f"
  run mi_conf_scan "$f"
  [ "$status" -eq 1 ]
  # `|| { …; return 1; }`, not a bare `[[ … ]]`: bash 3.2 does NOT apply errexit to a failing `[[ ]]`,
  # so on macOS a bare one continues and only the test's LAST command decides pass/fail. Verified on
  # 3.2.57. The explicit form is load-bearing on every bash.
  [[ "$output" == *"more than 1024 keys"* ]] \
    || { echo "the refusal does not name the cap: $output" >&2; return 1; }
}

# The cap has to make the refusal CHEAP, not merely eventual — bounding the work is the whole point.
# Timed in a SUBPROCESS so bats' per-command DEBUG trap is not part of the measurement. The threshold
# is deliberately loose: capped, this file is refused in well under a second; with the cap lifted the
# SAME file took 46s on the machine this was written on, so 10s separates the two without being able
# to fire on a slow machine.
@test "a file far over the key cap is refused quickly, not after a quadratic scan" {
  local f="$MYTHICAL_HOME/huge.conf" start elapsed
  many_keys 20000 "$f"
  [ "$(wc -c < "$f" | tr -d ' ')" -lt "$MI_CONF_MAXBYTES" ]   # inside the accepted size ceiling
  start="$SECONDS"
  run bash -c '
    for m in common layout config lock ledger; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    mi_conf_scan "$1"' _ "$f"
  elapsed=$(( SECONDS - start ))
  [ "$status" -eq 1 ]
  [ "$elapsed" -le 10 ] \
    || { echo "the refusal took ${elapsed}s — the cap is not bounding the quadratic scan" >&2; return 1; }
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

# Every byte-gate failure used to be reported as "contains control bytes (NUL, CR, TAB or similar)",
# including a file that exists and simply cannot be OPENED: the `tr` redirect fails, tr contributes
# nothing, and `cmp` therefore reports a difference. An operator with a permission problem was sent
# after a hostile-content problem — and the two remedies have nothing in common.
@test "an unreadable file is reported as unreadable, not as containing control bytes" {
  # Not staged as root: root reads a mode-000 file regardless, so there the fixture would simply be a
  # readable file and the test would assert the wrong thing rather than fail honestly.
  if [ "$EUID" -eq 0 ]; then skip "root bypasses mode 000, so an unreadable file cannot be staged"; fi
  local f="$MYTHICAL_HOME/locked.conf"
  printf 'MYTHICAL_NET=n\n' > "$f"
  chmod 000 "$f"
  run mi_conf_scan "$f"
  [ "$status" -eq 1 ]
  # Both directions matter, and both use the explicit form because bash 3.2 does not apply errexit to
  # a failing `[[ ]]` — a bare one here passed against the unfixed code, which reports the file as
  # byte-polluted.
  [[ "$output" == *"cannot read"* ]] \
    || { echo "an unreadable file was not reported as unreadable: $output" >&2; return 1; }
  [[ "$output" != *"control bytes"* ]] \
    || { echo "an unreadable file was blamed on control bytes: $output" >&2; return 1; }
  # …and the same file, readable, parses fine — so the message above is about the mode and nothing else.
  chmod 600 "$f"
  run mi_conf_scan "$f"
  [ "$status" -eq 0 ]
}

@test "a missing file reports rc 3, distinct from malformed" {
  run mi_conf_scan "$MYTHICAL_HOME/nope.conf"
  [ "$status" -eq 3 ]
}
