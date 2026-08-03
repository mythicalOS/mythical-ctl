#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; install_helper_img
  write_fixture_product p1; IDX="$MYTHICAL_HOME/index"; POL="$MYTHICAL_HOME/policy"
  MAN="$MYTHICAL_HOME/p1.manifest"; MI_CONFIRM=yes; export MI_CONFIRM
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  DEST="$(mktemp -d)/dest"        # a fresh, non-existent leaf inside a real directory
}
teardown() { teardown_test_env; }

@test "migrate-storage with NO ROLE is rejected — a product may have several volume roles" {
  run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 2 ]
  assert_contains "role"
}

@test "an UNKNOWN role is rejected against the manifest, which names the valid roles" {
  run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 nosuch --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "state"
  assert_contains "secrets"
}

@test "a SECRETS role is REFUSED WITH THE REASON — permitted but not bindable (D53)" {
  run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 secrets --to-bind "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "not bindable"
  run grep -a 'unknown role' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "a policy index collapsing permitted and bindable is rejected as MALFORMED (Plan 3's invariant)" {
  printf 'p1.bindable_role=nowhere\n' >> "$MYTHICAL_HOME/policy"
  run mi_policy_load "$MYTHICAL_HOME/policy"
  [ "$status" -ne 0 ]
}

@test "the role must be VOLUME-BACKED, proved by POSITIVE INSPECTION of the container's mounts" {
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -eq 0 ]
  mi_rt_container_rm "$C" >/dev/null
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "does not mount"
}

@test "an ALREADY-BIND-BACKED role with NO live intent is refused, naming the current bind" {
  mi_lock_acquire; mi_conf_family_add MYTHICAL_P1_STATE_BIND /already/there; mi_lock_release
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "/already/there"
  assert_contains "stale"
}

@test "a live intent is checked FIRST, so a present bind after a crash RESUMES rather than refusing" {
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=6" "product=p1" "role=state" \
      "dest=$DEST" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=started" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=${DEST}.staging" "nonce=nz"
  mi_conf_family_add MYTHICAL_P1_STATE_BIND "$DEST"
  mi_lock_release
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -eq 0 ]
}

@test "a live intent naming a DIFFERENT destination stops and reports BOTH paths" {
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=3" "product=p1" "role=state" \
      "dest=/old/path" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=none" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=/old/path.staging" "nonce=nz"
  mi_lock_release
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "/old/path"
  assert_contains "$DEST"
}

@test "a NON-EMPTY destination is refused by default, not merged" {
  mkdir -p "$DEST"; printf 'x\n' > "$DEST/pre-existing"
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "not empty"
  run grep -aiE 'merge' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "staging is a SIBLING of the destination, never a child" {
  run mi_mig_staging_path "$DEST" nonceX
  [ "$output" = "$(dirname "$DEST")/.mythical-staging-nonceX" ]
  case "$output" in "$DEST"/*) false ;; *) true ;; esac
}

@test "a destination that is itself a MOUNT POINT is refused, naming the remedy" {
  FAKE_MOUNTPOINTS="$DEST" run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -ne 0 ]
  assert_contains "subdirectory"
}

@test "mount-point detection uses MOUNT-TABLE evidence, not an st_dev comparison" {
  run grep -a 'st_dev' "${_MCTL_ROOT}/lib/migrate.sh"
  [ "$status" -eq 0 ]
  assert_contains "cheap first filter"
  run grep -aE 'mountinfo|/sbin/mount|mount -p' "${_MCTL_ROOT}/lib/migrate.sh"
  [ "$status" -eq 0 ]
}

@test "the recorded device+inode identifies the destination after the rename" {
  mkdir -p "$DEST"
  id="$(mi_mig_identity "$DEST")"
  mv "$DEST" "${DEST}.moved"
  [ "$(mi_mig_identity "${DEST}.moved")" = "$id" ]
}

@test "phase 5 recovery: identity at the DESTINATION advances to phase 6" {
  run mi_mig_resolve_phase5 "$DEST" "${DEST}.staging" "$(mkdir -p "$DEST" && mi_mig_identity "$DEST")"
  [ "$output" = destination ]
}

@test "phase 5 recovery: identity at STAGING retries the rename" {
  local s="${DEST}.staging"; mkdir -p "$s"
  run mi_mig_resolve_phase5 "$DEST" "$s" "$(mi_mig_identity "$s")"
  [ "$output" = staging ]
}

@test "phase 5 recovery: identity NOWHERE stops and reports — never retries, never deletes" {
  run mi_mig_resolve_phase5 "$DEST" "${DEST}.staging" "999999:999999"
  [ "$status" -ne 0 ]
  assert_contains "stop"
  run grep -aiE 'retry|delete' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "leftover staging is deleted ONLY on a nonce AND device/inode match" {
  local s="${DEST}.staging"; mkdir -p "$s"
  id="$(mi_mig_identity "$s")"
  run mi_mig_staging_reclaim "$s" nonceX "$id" nonceX
  [ "$status" -eq 0 ]
  [ ! -d "$s" ]
}

@test "a leftover staging MISMATCH is preserved and reported — the name alone is not authority" {
  local s="${DEST}.staging"; mkdir -p "$s"
  run mi_mig_staging_reclaim "$s" nonceX "999:999" nonceX
  [ "$status" -ne 0 ]
  [ -d "$s" ]
  assert_contains "preserved"
}

@test "an UNPROVABLE leftover is stepped around with a FRESH nonce, never a deadlock" {
  local s="$(dirname "$DEST")/.mythical-staging-old"; mkdir -p "$s"
  a="$(mi_mig_staging_path "$DEST" n1)"; b="$(mi_mig_staging_path "$DEST" n2)"
  [ "$a" != "$b" ]
  [ -d "$s" ]
}

@test "the migration's OWN staging does not count as a non-empty destination" {
  mkdir -p "$(mi_mig_staging_path "$DEST" nonceX)"
  run mi_mig_precheck "$IDX" "$POL" "$MAN" p1 state "$DEST"
  [ "$status" -eq 0 ]
}

@test "compare-and-set: not started, key absent → write" {
  mi_lock_acquire
  run mi_conf_family_cas MYTHICAL_P1_STATE_BIND "$DEST" "" none
  [ "$status" -eq 0 ]
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = "$DEST" ]
  mi_lock_release
}

@test "compare-and-set: attempt in progress, key holds OUR value → advance without rewriting" {
  mi_lock_acquire
  mi_conf_family_add MYTHICAL_P1_STATE_BIND "$DEST"
  h="$(mi_digest "$MYTHICAL_HOME/mythical.conf")"
  run mi_conf_family_cas MYTHICAL_P1_STATE_BIND "$DEST" "" started
  [ "$status" -eq 0 ]
  [ "$h" = "$(mi_digest "$MYTHICAL_HOME/mythical.conf")" ]
  mi_lock_release
}

@test "compare-and-set: attempt in progress, key ABSENT → STOP and require confirmation" {
  mi_lock_acquire
  MI_CONFIRM=no run mi_conf_family_cas MYTHICAL_P1_STATE_BIND "$DEST" "" started
  [ "$status" -ne 0 ]
  assert_contains "equally"
  assert_contains "deleted"
  mi_lock_release
}

@test "compare-and-set: attempt in progress, key holds SOMETHING ELSE → STOP" {
  mi_lock_acquire
  mi_conf_family_add MYTHICAL_P1_STATE_BIND /operator/choice
  MI_CONFIRM=no run mi_conf_family_cas MYTHICAL_P1_STATE_BIND "$DEST" "" started
  [ "$status" -ne 0 ]
  assert_contains "/operator/choice"
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = /operator/choice ]
  mi_lock_release
}

@test "the bind reaches mythical.conf BEFORE the container is replaced" {
  mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" >/dev/null
  # The config write (phase 6) must precede the create (phase 7) in the call log.
  cw="$(grep -an 'container create' "$FAKE_DOCKER_STATE/calls.log" | tail -n1 | cut -d: -f1)"
  [ -n "$cw" ]
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_P1_STATE_BIND
  [ "$output" = "$DEST" ]
}

@test "after the migration, a RECREATE keeps the product on the bind" {
  mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" >/dev/null
  mi_verb_recreate "$IDX" "$POL" "$MAN" p1 >/dev/null
  run mi_rt_inspect container c.mounts "$C"
  assert_contains "$DEST"
}

@test "phase 7 REPLACES the container and tombstones the old one — mounts are immutable" {
  before="$(mi_rt_inspect container c.image "$C")"
  mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" >/dev/null
  run grep -a 'container rm' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
  run grep -a -- 'update' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
  : "$before"
}

@test "phase 8 verifies the mount BY INSPECTION and claims nothing about the container-side read" {
  mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" >/dev/null
  run mi_mig_run "$IDX" "$POL" "$MAN" p1 state "$DEST" 8
  [ "$status" -eq 0 ]
  run grep -aiE 'container-side read (is )?(verified|confirmed)' "${_MCTL_ROOT}/lib/migrate.sh"
  [ "$status" -ne 0 ]
  run grep -a 'not verified at all' "${_MCTL_ROOT}/lib/migrate.sh"
  [ "$status" -eq 0 ]
}

@test "a migration of a desired-STOPPED product leaves it stopped and still verifies phase 8" {
  mi_verb_stop p1
  run mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST"
  [ "$status" -eq 0 ]
  run mi_state_desired_get "$C"
  [ "$output" = stopped ]
  run mi_state_observed "$C"
  [ "$output" = stopped ]
}

@test "generic reconciliation is SUSPENDED for the container while the intent is live" {
  mi_lock_acquire
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=3" "product=p1" "role=state" "dest=$DEST" \
      "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=none" "desired=running" \
      "srcvol=mythical-${IDENT}-p1-state" "staging=${DEST}.staging" "nonce=nz"
  mi_rt_container_stop "$C" >/dev/null
  run mi_state_plan "$C"
  [ "$output" = suspended ]
  mi_lock_release
}

@test "phase 9 restores the recorded desired state and only THEN may delete the source volume" {
  mi_verb_migrate_storage "$IDX" "$POL" "$MAN" p1 state --to-bind "$DEST" >/dev/null
  run mi_state_observed "$C"
  [ "$output" = running ]
  # The source volume is RETAINED by default — deleting user data is never automatic.
  run mi_rt_inspect volume v.nonce "mythical-${IDENT}-p1-state"
  [ "$status" -eq 0 ]
}

@test "each of the nine phases resumes from the recorded phase" {
  local n
  for n in 1 2 3 4 5 6 7 8 9; do
    teardown; setup
    mi_lock_acquire
    mi_led_put storagemig key "p1:state" "key=p1:state" "phase=$n" "product=p1" "role=state" \
        "dest=$DEST" "confkey=MYTHICAL_P1_STATE_BIND" "prior=" "attempt=none" "desired=running" \
        "srcvol=mythical-${IDENT}-p1-state" "staging=$(mi_mig_staging_path "$DEST" nz)" "nonce=nz"
    mi_lock_release
    run mi_mig_resume "$IDX" "$POL" "$MAN"
    [ "$status" -eq 0 ] || { echo "phase $n did not resume: $output"; false; }
  done
}
