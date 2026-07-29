#!/usr/bin/env bats
load '../lib/test_helper'

# setup_test_env FIRST — see the note in Task 1 Step 4. Without it mi_ensure_layout would create
# ~/.mythical in the engineer's real home and these tests would write there.
setup() {
  setup_test_env
  load_mctl
  mi_ensure_layout
  mi_lock_acquire
}
# No teardown() here: the helper's teardown removes MYTHICAL_HOME, and the lock file goes with it.
# Defining one would replace the helper's and leak a temp directory per test.

@test "the path is ~/.mythical/mythical.conf" {
  [ "$(mi_conf_family_path)" = "$MYTHICAL_HOME/mythical.conf" ]
}

@test "the first set creates the file at mode 0600" {
  mi_conf_family_add MYTHICAL_NET mythical-net
  local f; f="$(mi_conf_family_path)"
  [ -f "$f" ]
  [ "$(ls -l "$f" | awk 'NR==1{print substr($1,1,10)}')" = "-rw-------" ]
  [ "$(mi_conf_get "$f" MYTHICAL_NET)" = "mythical-net" ]
}

# §10a: "install a second product — mythical.conf gains keys additively".
@test "a second key is added additively, leaving the first untouched" {
  mi_conf_family_add MYTHICAL_NET mythical-net
  mi_conf_family_add MYTHICAL_TELEMETRY_KEY abc123
  local f; f="$(mi_conf_family_path)"
  [ "$(mi_conf_get "$f" MYTHICAL_NET)" = "mythical-net" ]
  [ "$(mi_conf_get "$f" MYTHICAL_TELEMETRY_KEY)" = "abc123" ]
}

# §10a: "re-install over a populated home — user-owned files byte-identical, including an
# operator's hand edit". Adding a NEW key must leave every existing byte untouched.
@test "adding a key preserves comments, blank lines, order and unrelated keys byte-for-byte" {
  local f; f="$(mi_conf_family_path)"
  cat > "$f" <<'EOF'
# operator's own header

MYTHICAL_NET=their-net
# a comment they wrote

# trailing note
EOF
  chmod 600 "$f"
  mi_conf_family_add MYTHICAL_TELEMETRY_KEY added
  cat > "$MYTHICAL_HOME/expected" <<'EOF'
# operator's own header

MYTHICAL_NET=their-net
# a comment they wrote

# trailing note
MYTHICAL_TELEMETRY_KEY=added
EOF
  diff -u "$MYTHICAL_HOME/expected" "$f"
}

# D9, and the whole reason this primitive is additive: the installer cannot distinguish its own
# earlier value from something the operator typed, so it must never replace one.
@test "adding a key that already holds a DIFFERENT value is refused, and the file is untouched" {
  local f; f="$(mi_conf_family_path)"
  printf '# hi\nMYTHICAL_NET=their-choice\n' > "$f"; chmod 600 "$f"
  cp "$f" "$MYTHICAL_HOME/before"
  run mi_conf_family_add MYTHICAL_NET our-default
  [ "$status" -ne 0 ]
  [[ "$output" == *their-choice* ]]
  diff -u "$MYTHICAL_HOME/before" "$f"
}

@test "adding a key that already holds the SAME value is a no-op success" {
  local f; f="$(mi_conf_family_path)"
  printf '# hi\nMYTHICAL_NET=same\n' > "$f"; chmod 600 "$f"
  cp "$f" "$MYTHICAL_HOME/before"
  run mi_conf_family_add MYTHICAL_NET same
  [ "$status" -eq 0 ]
  diff -u "$MYTHICAL_HOME/before" "$f"
}

@test "a call with the wrong number of arguments refuses instead of aborting under set -u" {
  run bash -c 'set -euo pipefail
    for m in common layout config lock ledger; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    mi_conf_family_add MYTHICAL_NET; echo UNREACHABLE'
  [ "$status" -ne 0 ]
  [[ "$output" != *UNREACHABLE* ]]
  [[ "$output" != *"unbound variable"* ]]
}

@test "a new key is appended at the end, after existing content" {
  local f; f="$(mi_conf_family_path)"
  printf '# hi\nMYTHICAL_NET=n\n' > "$f"; chmod 600 "$f"
  mi_conf_family_add MYTHICAL_TELEMETRY_KEY t
  [ "$(tail -n1 "$f")" = "MYTHICAL_TELEMETRY_KEY=t" ]
  [ "$(head -n1 "$f")" = "# hi" ]
}

@test "a value invalid for its type is refused before the additive gate" {
  run mi_conf_family_add MYTHICAL_NET host
  [ "$status" -ne 0 ]
  [ ! -f "$(mi_conf_family_path)" ]
}

@test "a value that would forge a second key is refused" {
  run mi_conf_family_add MYTHICAL_TELEMETRY_KEY "$(printf 'a\nMYTHICAL_NET=evil')"
  [ "$status" -ne 0 ]
  [ ! -f "$(mi_conf_family_path)" ]
}

@test "a value with a shell metacharacter is refused" {
  run mi_conf_family_add MYTHICAL_TELEMETRY_KEY 'a$(id)b'
  [ "$status" -ne 0 ]
}

@test "a key outside the core spec is refused" {
  run mi_conf_family_add MYTHICAL_NOT_A_REAL_KEY x
  [ "$status" -ne 0 ]
}

@test "a value invalid for its type is refused" {
  run mi_conf_family_add MYTHICAL_NET host
  [ "$status" -ne 0 ]
}

# The gate is the FULL load, not the syntax scan: a file carrying a key outside the core schema
# scans perfectly and fails mi_conf_family_load, so gating on the scan would let this "succeed"
# while producing a file its own reader rejects.
@test "an existing file with an off-schema key is never modified" {
  local f; f="$(mi_conf_family_path)"
  printf 'MYTHICAL_UNKNOWN=x\n' > "$f"; chmod 600 "$f"
  cp "$f" "$MYTHICAL_HOME/before"
  run mi_conf_family_add MYTHICAL_NET n
  [ "$status" -ne 0 ]
  diff -u "$MYTHICAL_HOME/before" "$f"
}

# D3 and D9 both expect writers the family lock cannot reach — the operator's editor, and the
# product's UI. A save landing between our read and our write must be refused, not discarded.
@test "a change landing under us is refused, not overwritten" {
  local f; f="$(mi_conf_family_path)"
  mi_conf_family_add MYTHICAL_NET first
  cp "$f" "$MYTHICAL_HOME/before"
  # stand in for a concurrent writer: report the file as changed
  _mi_conf_unchanged() { return 1; }
  run mi_conf_family_add MYTHICAL_TELEMETRY_KEY t
  [ "$status" -ne 0 ]
  [[ "$output" == *"changed while we were reading it"* ]]
  diff -u "$MYTHICAL_HOME/before" "$f"
}

@test "an existing file that does not parse is never overwritten" {
  local f; f="$(mi_conf_family_path)"
  printf 'MYTHICAL_NET=`id`\n' > "$f"; chmod 600 "$f"
  cp "$f" "$MYTHICAL_HOME/before"
  run mi_conf_family_add MYTHICAL_TELEMETRY_KEY t
  [ "$status" -ne 0 ]
  diff -u "$MYTHICAL_HOME/before" "$f"
}

@test "mi_conf_family_load validates against the core spec" {
  local f; f="$(mi_conf_family_path)"
  printf 'MYTHICAL_NET=n\n' > "$f"; chmod 600 "$f"
  run mi_conf_family_load
  [ "$status" -eq 0 ]
  [ "$output" = "$(printf 'MYTHICAL_NET\tn')" ]
}

@test "writing without the family lock is refused" {
  mi_lock_release
  run bash -c 'set -euo pipefail
    source "'"$_MCTL_ROOT"'/lib/common.sh"
    source "'"$_MCTL_ROOT"'/lib/layout.sh"
    source "'"$_MCTL_ROOT"'/lib/config.sh"
    source "'"$_MCTL_ROOT"'/lib/lock.sh"
    mi_conf_family_add MYTHICAL_NET n'
  [ "$status" -ne 0 ]
  [[ "$output" == *"family lock"* ]]
  [ ! -f "$(mi_conf_family_path)" ]
}

@test "a forged lock token does not authorize a write" {
  MI_LOCK_TOKEN="not-the-real-token"
  run mi_conf_family_add MYTHICAL_NET n
  [ "$status" -ne 0 ]
  [[ "$output" == *"family lock"* ]]
}

@test "the ledger's lock refusal is unchanged by the extraction" {
  mi_lock_release
  run bash -c 'set -euo pipefail
    source "'"$_MCTL_ROOT"'/lib/common.sh"
    source "'"$_MCTL_ROOT"'/lib/layout.sh"
    source "'"$_MCTL_ROOT"'/lib/config.sh"
    source "'"$_MCTL_ROOT"'/lib/lock.sh"
    source "'"$_MCTL_ROOT"'/lib/ledger.sh"
    printf "" | mi_ledger_write'
  [ "$status" -ne 0 ]
  [[ "$output" == *"refusing to write the ledger without holding the family lock"* ]]
}
