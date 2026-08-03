#!/usr/bin/env bats
# §10a — backup and restore through the ACTUAL CLI/verb layer: confirmation, locking, arity, and the
# §7.3 exit-code contract. tests/unit/backup.bats already exercises the library functions directly
# (mi_backup_run/mi_restore_run/mi_restore_abandon) under a lock the suite holds itself; this file goes
# through mi_verb_backup/mi_verb_restore and bin/mythical-ctl instead, which acquire their own lock and
# apply their own confirmation gates — the shape an operator actually drives.
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; install_helper_img
  write_fixture_product p1; IDX="$MYTHICAL_HOME/index"; POL="$MYTHICAL_HOME/policy"
  MAN="$MYTHICAL_HOME/p1.manifest"; MI_CONFIRM=yes; export MI_CONFIRM
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  VOL_STATE="$(mi_name_volume "$IDENT" p1 state)"
  VOL_SECRETS="$(mi_name_volume "$IDENT" p1 secrets)"
  # See tests/unit/backup.bats's setup() for why: install() leaves the product's own container
  # mounting both volumes, and the fake daemon (like a real one) refuses to remove a volume a
  # container still mounts — removing it here keeps every test about restore's own logic, not about
  # an unrelated "volume in use" refusal from a container these tests never restart.
  mi_lock_acquire; mi_rt_container_rm "$(mi_name_container "$IDENT" p1)" >/dev/null 2>&1 || true; mi_lock_release
  BK="$(mktemp -d)/backup"
}
teardown() { rm -rf "$(dirname "$BK")"; teardown_test_env; }

# --- the full round trip, through the verbs ---------------------------------------------------------

@test "backup then restore: a full round trip through mi_verb_backup/mi_verb_restore" {
  run mi_verb_backup "$IDX" "$BK"
  assert_ok
  [ -f "$BK/ledger" ]
  [ -f "$BK/volumes/${VOL_STATE}.nonce" ]
  [ -f "$BK/volumes/${VOL_SECRETS}.nonce" ]

  rm -f "$MYTHICAL_HOME/.state/ledger"
  run mi_verb_restore "$IDX" "$BK"
  assert_ok
  assert_contains "activated"

  for v in "$VOL_STATE" "$VOL_SECRETS"; do
    run mi_prov_authority volume "$v"
    assert_ok
  done
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

@test "backup then restore: through the actual CLI (bin/mythical-ctl)" {
  run_mctl backup "$BK" --index "$IDX"
  [ "$status" -eq 0 ]

  rm -f "$MYTHICAL_HOME/.state/ledger"
  run_mctl restore "$BK" --index "$IDX"
  [ "$status" -eq 0 ]
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

# --- CLI arity and option scoping ------------------------------------------------------------------

@test "CLI: backup needs exactly one operand (the output directory)" {
  run_mctl backup --index "$IDX"
  [ "$status" -eq 2 ]
  run_mctl backup "$BK" extra --index "$IDX"
  [ "$status" -eq 2 ]
}

@test "CLI: restore needs exactly one operand, or --abandon alone, never both" {
  run_mctl restore --index "$IDX"
  [ "$status" -eq 2 ]
  run_mctl restore "$BK" --abandon --index "$IDX"
  [ "$status" -eq 2 ]
  run_mctl restore "$BK" extra --index "$IDX"
  [ "$status" -eq 2 ]
}

@test "CLI: backup refuses options that belong to other verbs" {
  run_mctl backup "$BK" --purge --index "$IDX"
  [ "$status" -eq 2 ]
  run_mctl backup "$BK" --to-bind /tmp/x --index "$IDX"
  [ "$status" -eq 2 ]
}

@test "CLI: restore refuses options that belong to other verbs" {
  run_mctl restore "$BK" --family --index "$IDX"
  [ "$status" -eq 2 ]
}

@test "CLI: --abandon on other verbs is refused, not silently ignored" {
  run_mctl install p1 --abandon --index "$IDX" --policy "$POL" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 2 ]
}

@test "mi_verb_backup/mi_verb_restore reject the wrong number of arguments as a usage error" {
  run mi_verb_backup "$IDX"
  [ "$status" -eq 2 ]
  run mi_verb_backup "$IDX" "$BK" extra
  [ "$status" -eq 2 ]
  run mi_verb_restore "$IDX"
  [ "$status" -eq 2 ]
}

# --- restore refuses over a live installation -------------------------------------------------------

@test "restore through the verb refuses while the current installation is still active" {
  mi_verb_backup "$IDX" "$BK" >/dev/null
  run mi_verb_restore "$IDX" "$BK"
  [ "$status" -eq 1 ]
  assert_contains "active installer state ledger is present"
  # the live installation is untouched
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

# --- resume after a crash, through the verb ---------------------------------------------------------

@test "a crash during fill resumes cleanly on the next mi_verb_restore call" {
  mi_verb_backup "$IDX" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  FAKE_DOCKER_INTERRUPT_AFTER='container run' run mi_verb_restore "$IDX" "$BK"
  [ "$status" -ne 0 ]
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]
  [ ! -f "$MYTHICAL_HOME/.state/ledger" ]

  run mi_verb_restore "$IDX" "$BK"
  assert_ok
  [ -f "$MYTHICAL_HOME/.state/ledger" ]
  [ ! -e "$MYTHICAL_HOME/.state/ledger.staging" ]
  run mi_ident_get
  [ "$output" = "$IDENT" ]
}

@test "a same-name survivor volume is refused end to end, and abandonment PRESERVES it" {
  mi_verb_backup "$IDX" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  mi_lock_acquire
  mi_rt_volume_rm "$VOL_STATE" >/dev/null 2>&1
  mi_rt_volume_create "$VOL_STATE" "an-unrelated-nonce" "an-unrelated-identity" >/dev/null
  mi_lock_release

  run mi_verb_restore "$IDX" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "SURVIVOR"
  # The staging ledger is written (phase 1) before the per-volume survivor check (phase 2) ever runs,
  # so an in-progress restore genuinely exists here — 'restore --abandon' (the correct 2-operand form)
  # is the recovery path, never a blind retry with the same directory.
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]

  MI_CONFIRM=yes run mi_verb_restore "$IDX" --abandon
  assert_ok
  assert_contains "PRESERVED"
  assert_contains "$VOL_STATE"
  # A same-name survivor is never abandoned or removed automatically: abandon only touches volumes
  # THIS restore attempt itself created (matching its recorded nonce), and this one was never that
  # restore's to begin with — it is left exactly as it was.
  run mi_rt_inspect volume v.nonce "$VOL_STATE"
  [ "$output" = "an-unrelated-nonce" ]
  [ ! -e "$MYTHICAL_HOME/.state/ledger.staging" ]
}

# --- abandonment through the verb, with confirmation -------------------------------------------------

@test "restore --abandon through the CLI removes the partial volumes with confirmation" {
  run_mctl backup "$BK" --index "$IDX"
  [ "$status" -eq 0 ]
  rm -f "$MYTHICAL_HOME/.state/ledger"
  FAKE_DOCKER_INTERRUPT_AFTER='container run' run_mctl restore "$BK" --index "$IDX"
  [ "$status" -ne 0 ]
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]

  MI_CONFIRM=no run_mctl restore --abandon --index "$IDX"
  [ "$status" -ne 0 ]
  [ -f "$MYTHICAL_HOME/.state/ledger.staging" ]      # untouched without confirmation

  MI_CONFIRM=yes run_mctl restore --abandon --index "$IDX"
  [ "$status" -eq 0 ]
  [ ! -e "$MYTHICAL_HOME/.state/ledger.staging" ]
  run mi_rt_inspect volume v.nonce "$VOL_STATE"
  [ "$status" -eq 3 ]
}

# --- corrupt staging, through the verb ---------------------------------------------------------------

@test "a corrupt staging ledger is preserved aside and blocks both restore and abandon, through the verb" {
  mi_verb_backup "$IDX" "$BK" >/dev/null
  rm -f "$MYTHICAL_HOME/.state/ledger"
  printf 'not a valid ledger\n' > "$MYTHICAL_HOME/.state/ledger.staging"

  run mi_verb_restore "$IDX" "$BK"
  [ "$status" -ne 0 ]
  assert_contains "does not validate"

  MI_CONFIRM=yes run mi_verb_restore "$IDX" "$BK" --abandon
  [ "$status" -eq 2 ]   # --abandon takes no backup-directory operand
}
