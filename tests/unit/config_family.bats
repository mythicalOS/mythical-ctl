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
  [[ "$output" == *their-choice* ]] || { echo "the refusal does not quote the operator's existing value: $output" >&2; return 1; }
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
  [[ "$output" != *UNREACHABLE* ]] || { echo "execution continued past the refusal: $output" >&2; return 1; }
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
  [[ "$output" == *"changed while we were reading it"* ]] || { echo "the refusal does not name the concurrent change: $output" >&2; return 1; }
  diff -u "$MYTHICAL_HOME/before" "$f"
}

# A digest compare-and-swap cannot see an A -> B -> A sequence, so validating the live file and then
# separately copying it is not enough: a writer that swaps in other bytes for the duration of the copy
# and restores the original before the digest check wins. Found by a cross-model review after four
# same-model reviews had passed over this function.
#
# Measured against the pre-fix code with this exact shim: rc **0**, the operator's comment header and
# their existing key DESTROYED, an unvalidated MYTHICAL_EVIL=pwned persisted, and the resulting file
# refused by mythical.conf's own reader — success reported while breaking the D9 non-destructive
# invariant. The fix is structural, so this test guards the structure: copy once, then validate, gate
# and digest THAT copy.
@test "bytes swapped in during the copy are validated, not persisted" {
  local shim="$BATS_TEST_TMPDIR/shim" f
  mkdir -p "$shim"
  cat > "$shim/cat" <<'EOF'
#!/bin/bash
# Stand in for a concurrent writer: off-schema bytes for the duration of the copy, original restored
# byte-for-byte before anyone can digest the live file again.
if [ "$1" = "$RACE_TARGET" ]; then
  cp "$RACE_TARGET" "$RACE_TARGET.orig"
  printf 'MYTHICAL_EVIL=pwned\n' > "$RACE_TARGET"
  /bin/cat "$RACE_TARGET"
  cp "$RACE_TARGET.orig" "$RACE_TARGET"
  rm -f "$RACE_TARGET.orig"
  exit 0
fi
exec /bin/cat "$@"
EOF
  chmod +x "$shim/cat"

  f="$(mi_conf_family_path)"
  printf '# operator header\nMYTHICAL_TELEMETRY_KEY=ok\n' > "$f"; chmod 600 "$f"
  cp "$f" "$MYTHICAL_HOME/before"

  RACE_TARGET="$f" PATH="$shim:$PATH" run mi_conf_family_add MYTHICAL_NET good-net
  [ "$status" -ne 0 ]
  # the swapped-in bytes were seen and refused, rather than copied and blessed
  [[ "$output" == *"does not load cleanly"* ]] \
    || { echo "the refusal does not name the unreadable content: $output" >&2; return 1; }
  # and the operator's file is byte-identical, so nothing was destroyed on the way
  diff -u "$MYTHICAL_HOME/before" "$f"
  mi_conf_family_load >/dev/null
}

# The no-op-success path reads its answer from a SNAPSHOT, so it has to confirm the live file still
# matches before reporting "already set". Returning 0 on the strength of bytes that may since have been
# replaced tells a caller the setting it asked for is present when it is not, and a caller told that has
# no reason to look again. mi_conf_product_add cannot have this bug because it always reaches its CAS;
# this writer's early return skipped it.
@test "same-value no-op does not report success if the file changed under us" {
  local f; f="$(mi_conf_family_path)"
  mi_conf_family_add MYTHICAL_NET same
  cp "$f" "$MYTHICAL_HOME/before"
  # stand in for an editor save landing after the snapshot was taken
  _mi_conf_unchanged() { return 1; }
  run mi_conf_family_add MYTHICAL_NET same
  [ "$status" -ne 0 ]
  [[ "$output" == *"changed while we were reading it"* ]] \
    || { echo "the no-op path reported success despite a concurrent change: $output" >&2; return 1; }
  diff -u "$MYTHICAL_HOME/before" "$f"
}

# --- identity (hardening, beyond what the plan scoped) --------------------------------------------
# The plan put the §4.1a identity checks on the container-writable <product>.conf only, reasoning that
# mythical.conf is host-only and not attacker-controlled. True of the threat, and it still left a bad
# failure mode. Reproduced before the check was added here: with mythical.conf planted as a SYMLINK to
# a file holding MYTHICAL_NET=planted, mi_conf_family_add returned 0, replaced the symlink with a real
# 0600 file, left the link target untouched — and ADOPTED the target's content into mythical.conf,
# while the value the installer was asked to write ended up in a file nothing reads. It reported
# success. Bounded (the attacker must already be able to create files in ~/.mythical/ as the operator,
# who could write mythical.conf directly), so no privilege is gained — but "silently adopts foreign
# content and reports success" is not a failure mode to ship.
# The identity check at the top of the writer is true only of the instant it ran. A symlink swapped in
# afterwards is copied from, validated, hashed, and then replaced by `mv` — and the digest CAS is
# satisfied, because it digests the link target both times. So without a second check immediately
# before the replace, the hardening comment's claim is false. `_mi_conf_unchanged` is the last thing
# that touches the live path before the replace, so overriding it is the precise hook for planting the
# swap deterministically.
@test "a symlink planted after the first identity check is still refused before the replace" {
  local f foreign; f="$(mi_conf_family_path)"; foreign="$MYTHICAL_HOME/foreign.conf"
  printf 'MYTHICAL_TELEMETRY_KEY=foreign\n' > "$foreign"; chmod 600 "$foreign"
  printf 'MYTHICAL_TELEMETRY_KEY=ours\n'    > "$f";       chmod 600 "$f"
  cp "$foreign" "$MYTHICAL_HOME/foreign-before"

  # racer: replace the pathname with a symlink to a clean, schema-valid foreign file, then report the
  # file unchanged so the CAS lets us through to the replace.
  eval '_mi_conf_unchanged() { ln -sf "'"$foreign"'" "'"$f"'"; return 0; }'
  run mi_conf_family_add MYTHICAL_NET good-net
  [ "$status" -ne 0 ]
  [[ "$output" == *symlink* ]] \
    || { echo "the pre-replace identity check did not refuse the planted symlink: $output" >&2; return 1; }
  # the foreign file was neither written through nor adopted
  diff -u "$MYTHICAL_HOME/foreign-before" "$foreign"
}

@test "a symlinked mythical.conf is refused, not followed and adopted" {
  local f target
  f="$(mi_conf_family_path)"
  target="$MYTHICAL_HOME/planted-target"
  printf 'MYTHICAL_NET=planted\n' > "$target"; chmod 600 "$target"
  ln -s "$target" "$f"

  run mi_conf_family_add MYTHICAL_TELEMETRY_KEY tok
  [ "$status" -ne 0 ]
  # Explicit form, not a bare `[[ … ]]`: bash 3.2 does not apply errexit to a failing `[[ ]]`, so a
  # bare one continues and only the test's last command decides pass/fail. Verified on 3.2.57.
  [[ "$output" == *symlink* ]] || { echo "the refusal does not name the symlink: $output" >&2; return 1; }
  # still a symlink: nothing was created through it, and nothing replaced it with a real file
  [ -L "$f" ]
  # the target is byte-identical — neither written to nor adopted from
  [ "$(cat "$target")" = "MYTHICAL_NET=planted" ]
  [ "$(wc -l < "$target" | tr -d ' ')" -eq 1 ]
}

# The same gate refuses the other identity the symlink test cannot catch: a hardlink is a second name
# for the same inode, not a link at the path level, so `[ -L ]` passes it.
@test "a hardlinked mythical.conf is refused, leaving the other name untouched" {
  local f other
  f="$(mi_conf_family_path)"; other="$MYTHICAL_HOME/other-name"
  printf 'MYTHICAL_NET=n\n' > "$other"; chmod 600 "$other"
  ln "$other" "$f"

  run mi_conf_family_add MYTHICAL_TELEMETRY_KEY tok
  [ "$status" -ne 0 ]
  [[ "$output" == *hardlinked* ]] \
    || { echo "the refusal does not name the hardlink: $output" >&2; return 1; }
  [ "$(cat "$other")" = "MYTHICAL_NET=n" ]
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
  [[ "$output" == *"family lock"* ]] || { echo "the refusal does not name the family lock: $output" >&2; return 1; }
  [ ! -f "$(mi_conf_family_path)" ]
}

@test "a forged lock token does not authorize a write" {
  MI_LOCK_TOKEN="not-the-real-token"
  run mi_conf_family_add MYTHICAL_NET n
  [ "$status" -ne 0 ]
  [[ "$output" == *"family lock"* ]]
}

# The shared lock proof holds its own callers to the same arity discipline every public function here
# applies. Under `set -u` an unguarded `local what="$1"` aborts with bash's raw "unbound variable"
# instead of a refusal naming the problem — from the one function that authorizes every mutating
# write. It fails closed either way; this asserts the diagnostic survives too.
@test "mi_lock_assert_held refuses a no-argument call in its own words" {
  run bash -c 'set -euo pipefail
    for m in common layout config lock ledger; do source "'"$_MCTL_ROOT"'/lib/$m.sh"; done
    export MI_LOCK_TOKEN=whatever
    mi_lock_assert_held; echo UNREACHABLE'
  [ "$status" -ne 0 ]
  [[ "$output" != *UNREACHABLE* ]] || { echo "execution continued past the refusal: $output" >&2; return 1; }
  [[ "$output" != *"unbound variable"* ]] || { echo "aborted on an unbound variable instead of refusing: $output" >&2; return 1; }
  [[ "$output" == *"naming the operation"* ]]
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
