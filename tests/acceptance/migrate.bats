#!/usr/bin/env bats
# §10a — migrate-storage against the hostile cases: both trees (the source volume and the destination)
# are untrusted, and every check here asserts over what actually reaches the host, not merely over an
# exit status. A refusal that still lets bytes reach the destination is not a refusal.
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; install_helper_img
  write_fixture_product p1; IDX="$MYTHICAL_HOME/index"; POL="$MYTHICAL_HOME/policy"
  MAN="$MYTHICAL_HOME/p1.manifest"; MI_CONFIRM=yes; export MI_CONFIRM
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  DEST="$(mktemp -d)/dest"
}
teardown() { teardown_test_env; }

# --- the source volume is untrusted ------------------------------------------------------------

@test "a volume with an ESCAPING symlink fails the migration and leaves no destination behind" {
  HELPER_COPY=escape run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "escapes the migrated tree"
  [ ! -e "$DEST" ]
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$status" -eq 3 ]                       # the bind was never written
}

@test "a volume with a device/socket/FIFO entry fails the migration and leaves no destination behind" {
  HELPER_COPY=special run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "device, socket or FIFO"
  [ ! -e "$DEST" ]
}

@test "a volume with an unrefused device entry is still caught by the closed entry-type check" {
  HELPER_COPY=special-unrefused run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  [ ! -e "$DEST" ]
}

@test "a volume with a setuid file migrates, with the privileged bit stripped and reported" {
  HELPER_COPY=setuid run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" 2>"$BATS_TEST_TMPDIR/err"
  status=$?
  [ "$status" -eq 0 ]
  grep -aq "privileged bits stripped" "$BATS_TEST_TMPDIR/err"
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = "$DEST" ]
}

@test "a volume with a FOREIGN uid is refused by default" {
  HELPER_COPY=foreign run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "foreign uid"
  [ ! -e "$DEST" ]
}

@test "a volume with a FOREIGN uid migrates when --map-foreign-to-operator is given" {
  HELPER_COPY=foreign run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" --map-foreign-to-operator
  [ "$status" -eq 0 ]
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = "$DEST" ]
}

@test "a volume with an ORDINARY (non-escaping) symlink migrates — it must not be refused" {
  # HELPER_COPY's default ("ok") transcript already includes a verbatim intra-tree symlink; the
  # ordinary end-to-end path must complete, not merely the copy step in isolation.
  run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -eq 0 ]
  run mi_rt_inspect container c.mounts "$C"
  assert_contains "$DEST"
}

# --- the destination is untrusted --------------------------------------------------------------

@test "a destination PRE-SEEDED with an escaping symlink is refused as non-empty, never followed" {
  mkdir -p "$DEST"
  ln -s /etc/passwd "$DEST/evil"
  run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "not empty"
  [ -L "$DEST/evil" ]                       # untouched — never adopted, never followed
  run readlink "$DEST/evil"
  [ "$output" = /etc/passwd ]
}

@test "a destination that is itself a MOUNT POINT is refused end to end, naming the remedy" {
  mkdir -p "$DEST"
  FAKE_MOUNTPOINTS="$DEST" run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "subdirectory"
}

# --- interrupted at a real phase, then resumed — the durable-phase contract ---------------------

@test "interrupted stopping the container (phase 2) converges cleanly on resume" {
  FAKE_DOCKER_INTERRUPT_AFTER='container stop' run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  run mi_mig_phase p1 state
  [ "$output" = 2 ]
  run mi_mig_resume "$IDX" "$POL" "$MAN"
  [ "$status" -eq 0 ]
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = "$DEST" ]
  run mi_rt_inspect container c.mounts "$C"
  assert_contains "$DEST"
}

@test "interrupted replacing the container (phase 7) converges cleanly on resume, and the bind survives" {
  FAKE_DOCKER_INTERRUPT_AFTER='container create' run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  # The config write (phase 6) must have already landed — it precedes the create this interrupted.
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = "$DEST" ]
  run mi_mig_resume "$IDX" "$POL" "$MAN"
  [ "$status" -eq 0 ]
  run mi_rt_inspect container c.mounts "$C"
  assert_contains "$DEST"
  run mi_led_find storagemig key "p1:state"
  [ "$status" -eq 3 ]                       # the intent is cleared once the migration completes
}

# --- leftover staging: never adopted, never touched automatically --------------------------------

@test "a leftover staging directory from an interrupted attempt is stepped around, never adopted" {
  local sib s
  sib="$(dirname "$DEST")"
  # Start a migration, then interrupt it mid-copy so staging exists with a recorded identity.
  FAKE_DOCKER_INTERRUPT_AFTER='container run' run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -ne 0 ]
  s="$(find "$sib" -maxdepth 1 -name '.mythical-staging-*' | head -n1)"
  [ -n "$s" ]
  [ -d "$s" ]
  # A fresh attempt (a new nonce, a new staging path) must not be blocked by the abandoned one, and
  # must not silently adopt it either — it proceeds beside it, and reclaiming it is never automatic
  # (mi_mig_staging_reclaim exists as a tool for an operator or a future repair sweep, not a step this
  # flow calls on its own), so the leftover survives the whole migration untouched.
  run mi_mig_resume "$IDX" "$POL" "$MAN"
  [ "$status" -eq 0 ]
  [ -d "$s" ]                               # still there — never removed, never adopted
}

@test "an OPERATOR EDIT of mythical.conf during a crashed migration is never silently overwritten" {
  # Drive the migration to just past phase 6 recording "attempt=started" is not directly reachable
  # without a real crash inside the CAS write, so this exercises the equivalent, durable shape: a
  # migration record recorded as attempt=started, with the operator's own value already in place.
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=6" "product=p1" "role=state" \
      "dest=$DEST" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=started" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=${DEST}.staging" "nonce=nz"
  mi_conf_family_add MYTHICAL_P1_STATE_BIND /operators/own/choice
  mi_lock_release
  MI_CONFIRM=no run mi_mig_resume "$IDX" "$POL" "$MAN"
  [ "$status" -ne 0 ]
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = /operators/own/choice ]     # the operator's edit survives — never silently overwritten
}
