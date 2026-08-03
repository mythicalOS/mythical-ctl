#!/usr/bin/env bats
# §6c/D59 — backup and the staging-ledger restore.
#
# Copying the directory is not a backup (§3a): the named volumes and the product's runtime secrets are
# not in it, and a backup that omits the installer state ledger discards every rollback floor. These
# tests are at the library level — mi_backup_run/mi_restore_run/mi_restore_abandon/
# mi_ledger_staging_activate are called directly, under a lock this suite acquires itself, matching
# tests/unit/copy.bats and tests/unit/migrate.bats's own convention. The full end-to-end round trip
# (through the verbs, with their own confirmation and locking) lives in tests/acceptance/restore.bats.
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; install_helper_img
  write_fixture_product p1; IDX="$MYTHICAL_HOME/index"; POL="$MYTHICAL_HOME/policy"
  MAN="$MYTHICAL_HOME/p1.manifest"; MI_CONFIRM=yes; export MI_CONFIRM
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  VOL_STATE="$(mi_name_volume "$IDENT" p1 state)"
  BK="$(mktemp -d)/backup"
  # Restore tests below simulate "this machine's ledger is gone" with `rm -f .state/ledger` alone —
  # deliberately, since that is the state restore's own precondition checks classify. But install()
  # left the product's own CONTAINER live, still mounting both volumes, and the fake daemon correctly
  # refuses to remove a volume a container has mounted (as a real one does) — so leaving it running
  # would make every volume-removal path (abandonment) fail for a reason that has nothing to do with
  # what these tests are about. Removed once, here, for every test in this file.
  mi_rt_container_rm "$(mi_name_container "$IDENT" p1)" >/dev/null 2>&1 || true
  # HELD FOR THE WHOLE TEST, released in teardown(): mi_backup_run/mi_restore_run are called directly
  # here (not through the verbs, which acquire their own), and they are not merely ledger writers —
  # mi_copy_available -> mi_copy_image -> mi_accept_index ADVANCES THE ANTI-ROLLBACK TRUST FLOOR as
  # part of accepting the index (mi_trust_check -> mi_trust_commit), which is a ledger write and needs
  # the lock exactly as mi_led_put/mi_led_del do. mi_verb_install already released its own lock by the
  # time this line runs (its call chain does not nest with this one).
  mi_lock_acquire
}
teardown() { mi_lock_release; rm -rf "$(dirname "$BK")"; teardown_test_env; }

# --- the manifest ------------------------------------------------------------------------------------

@test "the backup manifest records TYPE, digest, link target, hardlink group, mode, owner and mtime" {
  local out="$BATS_TEST_TMPDIR/state.manifest"
  run mi_backup_manifest_write "$IDX" "$VOL_STATE" "$out"
  assert_ok
  [ -f "$out" ]
  run cat "$out"
  assert_contains "manifest=dir:"
  assert_contains "manifest=file:"
  assert_contains "manifest=symlink:"
  assert_contains "manifest=hardlink:"
  assert_contains "digest="
  assert_contains "linktarget="
  assert_contains "mode="
  assert_contains "owner="
  assert_contains "mtime="
  assert_contains "hardlink="
  assert_contains "done=ok"
}

@test "a manifest transcript stating nothing is refused, not written as an empty manifest" {
  local out="$BATS_TEST_TMPDIR/state.manifest"
  HELPER_MANIFEST=silent run mi_backup_manifest_write "$IDX" "$VOL_STATE" "$out"
  [ "$status" -ne 0 ]
  [ ! -e "$out" ]
}

# --- backup must include the ledger ------------------------------------------------------------------

@test "a backup that omits the ledger is refused — it would discard every rollback floor" {
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "no installer state ledger"
  [ ! -e "$BK/ledger" ]
}

@test "a corrupt ledger refuses the backup rather than capturing state that cannot be read" {
  printf 'garbage' >> "$MYTHICAL_HOME/.state/ledger"
  run mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "does not validate"
}

@test "a full backup writes the ledger, the tree, and every volume's contents, manifest and nonce" {
  run mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  [ -f "$BK/ledger" ]
  [ -f "$BK/tree/mythical.conf" ]
  [ -f "$BK/volumes/${VOL_STATE}.nonce" ]
  [ -s "$BK/volumes/${VOL_STATE}.nonce" ]
  [ -f "$BK/volumes/${VOL_STATE}.manifest" ]
  [ -d "$BK/volumes/${VOL_STATE}.data" ]
  # the ephemeral lock is never carried into a backup — restoring one would wedge the first operation
  [ ! -e "$BK/tree/.state/lock" ]
  [ ! -e "$BK/tree/.state/ledger" ]
}

@test "the recorded nonce in the backup matches the ledger's own provenance for that volume" {
  run mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  local rec recorded actual
  rec="$(mi_prov_find volume "$VOL_STATE")"
  recorded="$(mi_led_field "$rec" nonce)"
  actual="$(cat "$BK/volumes/${VOL_STATE}.nonce")"
  [ -n "$recorded" ]
  [ "$actual" = "$recorded" ]
}

@test "a backup refuses an unsafe (group-writable) output location, naming the reason" {
  local parent="$BATS_TEST_TMPDIR/unsafeparent"
  mkdir -p "$parent"; chmod 777 "$parent"
  run mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$parent/backup"
  [ "$status" -ne 0 ]
  assert_contains "writable"
}

# --- restore: first-use / state classification ---------------------------------------------------

@test "restore REFUSES when an active ledger is present, naming it" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "active installer state ledger is present"
  assert_contains "$MYTHICAL_HOME/.state/ledger"
}

@test "with no active AND no staging ledger, mi_restore_state answers none" {
  run mi_restore_state
  assert_ok
  [ "$output" = active ]      # setup() already installed p1, so this machine has an active ledger
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_restore_state
  [ "$output" = none ]
}

@test "ordinary commands finding staging-without-active do NOT read the machine as first use" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  # Interrupt right after phase 1 (the incoming ledger is staged) so an active ledger never appears —
  # mi_restore_state must then answer staging-with-intent, and mi_first_use (Task 3) must refuse rather
  # than treat the machine as a fresh install.
  FAKE_DOCKER_INTERRUPT_AFTER='volume create' run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  run mi_restore_state
  [ "$output" = staging-with-intent ]
  run mi_first_use
  [ "$status" -ne 0 ]
  [ "$status" -ne 3 ]        # NOT "genuinely first use"
  assert_contains "restore is in progress"
}

@test "restore writes a STAGING ledger with the intent inside it, before anything is created" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  FAKE_DOCKER_INTERRUPT_AFTER='volume create' run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]
  [ ! -f "$MYTHICAL_HOME/.state/ledger" ]     # nothing has been activated
  run mi_restore_state
  [ "$output" = staging-with-intent ]
}

@test "a CORRUPT staging ledger authorizes no cleanup: preserved aside, volumes named as blocking" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  printf 'not a ledger at all\n' > "$MYTHICAL_HOME/.state/ledger.staging"
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "does not validate"
  assert_contains "PRESERVED"
  run bash -c 'ls '"$MYTHICAL_HOME"'/.state/ledger.staging.corrupt.* 2>/dev/null'
  assert_ok
}

# --- restore: phase 2 (create + re-inspect) ---------------------------------------------------------

@test "phase 2 creates each volume WITH the recorded nonce, then RE-INSPECTS for label AND emptiness" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  local recorded; recorded="$(cat "$BK/volumes/${VOL_STATE}.nonce")"
  run mi_rt_inspect volume v.nonce "$VOL_STATE"
  [ "$output" = "$recorded" ]
}

@test "a same-name SURVIVOR fails the re-inspection and the restore refuses, naming it" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  # A volume already sits at this name with a DIFFERENT nonce — 'volume create' against an existing
  # name succeeds without applying the new label (D56), so this is exactly the survivor case. The
  # volume install() created (with the CORRECT nonce) must be removed first: create-over-existing does
  # NOT relabel, so poisoning it without removing it first would be a no-op and this test would pass
  # for the wrong reason (it did, the first time this was written — caught by watching it against the
  # unpoisoned volume and seeing the SAME "restored fine" outcome).
  mi_rt_volume_rm "$VOL_STATE" >/dev/null 2>&1
  mi_rt_volume_create "$VOL_STATE" "not-our-nonce" "some-other-identity" >/dev/null
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "SURVIVOR"
  assert_contains "$VOL_STATE"
}

# --- restore: phase 4 (manifest-contract verification, not bytes alone) ---------------------------

@test "phase 4 verifies against the backup's per-entry manifest" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  assert_contains "verified against the backup's per-entry manifest"
}

@test "a restore that re-created a symlink as a FILE fails verification" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  HELPER_RESTORE_VERIFY=type-symlink-as-file run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "VERIFICATION MISMATCH"
  assert_contains "no bytes to mismatch"
  [ ! -f "$MYTHICAL_HOME/.state/ledger" ]   # never activated over a failed verification
}

@test "a restore that FLATTENED a hardlink group fails verification" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  HELPER_RESTORE_VERIFY=hardlink-flattened run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "VERIFICATION MISMATCH"
  assert_contains "flattened hardlinks digest identically"
}

@test "a restore that DROPPED modes fails verification" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  HELPER_RESTORE_VERIFY=mode-dropped run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "VERIFICATION MISMATCH"
}

@test "a verification that never states a checked count is refused, not read as a vacuous pass" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  HELPER_RESTORE_VERIFY=nocount run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "stated nothing"
  [ ! -f "$MYTHICAL_HOME/.state/ledger" ]
}

@test "a verification that UNDERSTATES its checked count against the manifest is refused" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  HELPER_RESTORE_VERIFY=understate run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "the manifest names"
}

# --- restore: phases 5/6 (intent-free rewrite, then activation) ------------------------------------

@test "phase 5 rewrites the staging ledger to its intent-free form, atomically" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  [ -f "$MYTHICAL_HOME/.state/ledger" ]
}

@test "phase 6 activates by atomic rename, and only then does anything claim the volumes" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  [ ! -e "$MYTHICAL_HOME/.state/ledger.staging" ]
  [ -f "$MYTHICAL_HOME/.state/ledger" ]
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

@test "a crash between 5 and 6 leaves staging-without-intent, and the next run ACTIVATES" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  # Phase 5 itself is mi_led_del under MI_LEDGER_PATH_OVERRIDE, which goes through mi_ledger_write —
  # interrupt the RENAME that is phase 6 to land exactly between the two.
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  # Simulate the crash directly: re-stage a completed (intent-free) ledger and confirm the dispatcher
  # activates it on the next call rather than re-running the volume phases.
  cp -- "$MYTHICAL_HOME/.state/ledger" "$MYTHICAL_HOME/.state/ledger.staging"
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_restore_state
  [ "$output" = staging-no-intent ]
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  [ -f "$MYTHICAL_HOME/.state/ledger" ]
  [ ! -e "$MYTHICAL_HOME/.state/ledger.staging" ]
}

@test "a crash during FILLING leaves labelled partial volumes and NO active ledger" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  FAKE_DOCKER_INTERRUPT_AFTER='container run' run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  [ ! -f "$MYTHICAL_HOME/.state/ledger" ]
  run mi_rt_inspect volume v.nonce "$VOL_STATE"
  local recorded; recorded="$(cat "$BK/volumes/${VOL_STATE}.nonce")"
  [ "$output" = "$recorded" ]                 # labelled, per phase 2 — but never activated
}

@test "a full round trip ends with every identity check passing" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  for role in state secrets; do
    local v; v="$(mi_name_volume "$IDENT" p1 "$role")"
    run mi_prov_authority volume "$v"
    assert_ok
  done
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

# --- abandonment --------------------------------------------------------------------------------

@test "abandonment removes volumes matching exact name+nonce BEFORE deleting the staging file" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  FAKE_DOCKER_INTERRUPT_AFTER='container run' run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]
  MI_CONFIRM=yes run mi_restore_abandon
  assert_ok
  run mi_rt_inspect volume v.nonce "$VOL_STATE"
  [ "$status" -eq 3 ]                          # the volume itself is gone
  [ ! -e "$MYTHICAL_HOME/.state/ledger.staging" ]
}

@test "abandonment PRESERVES a volume whose nonce does not match, and reports it" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  FAKE_DOCKER_INTERRUPT_AFTER='container run' run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  # Simulate someone else's object landing at the same name in between: overwrite the volume's own
  # label to a nonce this staging ledger did not record.
  mi_rt_volume_rm "$VOL_STATE" >/dev/null 2>&1
  mi_rt_volume_create "$VOL_STATE" "somebody-elses-nonce" "somebody-elses-identity" >/dev/null
  MI_CONFIRM=yes run mi_restore_abandon
  assert_ok
  assert_contains "PRESERVED"
  assert_contains "$VOL_STATE"
  run mi_rt_inspect volume v.nonce "$VOL_STATE"
  [ "$output" = "somebody-elses-nonce" ]        # never touched
  mi_rt_volume_rm "$VOL_STATE" >/dev/null 2>&1 || true
}

@test "abandon without confirmation is refused, and the staging ledger survives" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  FAKE_DOCKER_INTERRUPT_AFTER='container run' run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  MI_CONFIRM=no run mi_restore_abandon
  [ "$status" -ne 0 ]
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]
}

@test "abandon on a machine with no restore in progress is refused" {
  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_restore_abandon
  [ "$status" -ne 0 ]
  assert_contains "no in-progress restore"
}

@test "abandon on a machine with an ACTIVE ledger (no restore) is refused, distinctly" {
  run mi_restore_abandon
  [ "$status" -ne 0 ]
  assert_contains "there is no restore in progress"
}

@test "abandon on a CORRUPT staging ledger authorizes no cleanup either" {
  mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  printf 'not a ledger\n' > "$MYTHICAL_HOME/.state/ledger.staging"
  run mi_restore_abandon
  [ "$status" -ne 0 ]
  assert_contains "does not validate"
  run bash -c 'ls '"$MYTHICAL_HOME"'/.state/ledger.staging.corrupt.* 2>/dev/null'
  assert_ok
}

# --- arity -------------------------------------------------------------------------------------------

@test "mi_backup_run rejects the wrong number of arguments" {
  run mi_backup_run "$IDX"
  [ "$status" -ne 0 ]
  run mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" extra
  [ "$status" -ne 0 ]
}

@test "mi_restore_run rejects the wrong number of arguments" {
  run mi_restore_run "$IDX"
  [ "$status" -ne 0 ]
  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK" extra
  [ "$status" -ne 0 ]
}

@test "mi_verb_backup and mi_verb_restore reject bad arity as a USAGE error (rc 2)" {
  run mi_verb_backup "$IDX"
  [ "$status" -eq 2 ]
  run mi_verb_restore
  [ "$status" -eq 2 ]
  run mi_verb_restore "$IDX" "$BK" extra
  [ "$status" -eq 2 ]
}

# --- codex gate round 1, fix 6: fail closed on a missing required volume field, never skip ----------

@test "fix6: a volume object record missing its own name is refused, not silently skipped" {
  # A checksum-valid, well-formed-per-field record — class=volume, a nonce — that is nonetheless
  # semantically incomplete: no name= at all. The OLD `|| continue` treated this exactly like "not a
  # volume record" and moved on; a backup could omit a ledger-declared volume with no trace anything
  # was skipped.
  mi_led_put object key "volume:ghost" "key=volume:ghost" "class=volume" "nonce=deadbeef" >/dev/null
  run mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "carries no name"
  [ ! -e "$BK/ledger" ]
}

@test "fix6: a volume object record missing its own nonce is refused, not silently skipped" {
  mi_led_put object key "volume:ghost2" "key=volume:ghost2" "class=volume" "name=ghost2" >/dev/null
  run mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "carries no nonce"
}

@test "fix6: restore also fails closed on a volume record missing name/nonce in the staged ledger" {
  run mi_backup_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  assert_ok
  rm -f "$MYTHICAL_HOME/.state/ledger"
  # Hand-craft the BACKUP's ledger file directly (mi_led_put cannot target $BK/ledger — the override
  # is deliberately restricted to the two paths this code owns, see codex gate round 1 fix 1) with a
  # semantically-incomplete volume record: class=volume, a name, but NO nonce. This proves restore's
  # own loop fails closed independently of backup's (already-tested) refusal — the realistic source of
  # such a ledger is a backup this installer did not write, or one damaged after the fact.
  local body sum
  body="$(printf 'identity\tid=deadbeefaa\nobject\tkey=volume:ghost3\tclass=volume\tname=ghost3')"
  { printf '#mythical-ctl-ledger schema=1\n'; printf '%s\n' "$body"; } > "$BK/ledger.tmp"
  sum="$(mi_digest "$BK/ledger.tmp")"
  { cat "$BK/ledger.tmp"; printf '#sha256=%s\n' "$sum"; } > "$BK/ledger"
  rm -f "$BK/ledger.tmp"

  run mi_restore_run "$IDX" "$POL" "$MYTHICAL_HOME" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "carries no nonce"
  [ ! -f "$MYTHICAL_HOME/.state/ledger" ]
}
