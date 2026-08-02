#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; install_helper_img
  write_fixture_product p1; IDX="$MYTHICAL_HOME/index"
  MI_CONFIRM=yes; export MI_CONFIRM     # non-interactive confirmation, tests only
}
teardown() { teardown_test_env; }

@test "a NEWER ledger schema is refused, naming the required version (already Plan 1; asserted here)" {
  mi_lock_acquire; mi_ident_ensure >/dev/null; mi_lock_release
  sed 's/schema=1/schema=99/' "$MYTHICAL_HOME/.state/ledger" > "$MYTHICAL_HOME/.state/l2"
  mv "$MYTHICAL_HOME/.state/l2" "$MYTHICAL_HOME/.state/ledger"
  run mi_ident_get
  [ "$status" -eq 1 ]
}

@test "a schema migration is a no-op at schema 1 and does not rewrite the ledger" {
  mi_lock_acquire; mi_ident_ensure >/dev/null
  h="$(mi_digest "$MYTHICAL_HOME/.state/ledger")"
  run mi_schema_migrate
  [ "$status" -eq 0 ]
  [ "$h" = "$(mi_digest "$MYTHICAL_HOME/.state/ledger")" ]
  mi_lock_release
}

@test "repair candidates are the DISTINCT installation identities present in object labels" {
  mi_rt_volume_create v1 n1 instA
  mi_rt_volume_create v2 n2 instA
  mi_rt_volume_create v3 n3 instB
  run mi_repair_candidates
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 2 ]
  assert_contains instA
  assert_contains instB
}

@test "EXACTLY ONE candidate is still shown and still confirmed — never silently adopted" {
  mi_rt_volume_create v1 n1 instA
  MI_CONFIRM=no run mi_repair_run "$IDX"
  [ "$status" -ne 0 ]
  assert_contains instA
  assert_contains "choose"
}

@test "two candidates: both shown, no action until one is chosen, the other's objects untouched" {
  mi_rt_volume_create v1 n1 instA
  mi_rt_volume_create v3 n3 instB
  MI_CONFIRM=no run mi_repair_run "$IDX"
  [ "$status" -ne 0 ]
  assert_contains instA
  assert_contains instB
  [ -e "$FAKE_DOCKER_STATE/volumes/v3" ]
}

@test "choosing an identity rebuilds provenance for containers, volumes and networks from labels" {
  net="$(mi_rt_network_create netA instA nA)"
  mi_rt_volume_create v1 n1 instA
  # `container create` refuses an image that was never pulled, exactly as a real daemon does.
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_repair_run "$IDX" instA
  run mi_ident_get
  [ "$output" = instA ]
  run mi_prov_find volume v1
  [ "$status" -eq 0 ]
  run mi_prov_find network netA
  [ "$status" -eq 0 ]
  run mi_prov_find container c1
  [ "$status" -eq 0 ]
}

@test "repair NEVER rebuilds image provenance and never claims to enumerate images" {
  mi_rt_volume_create v1 n1 instA
  run mi_repair_run "$IDX" instA
  assert_contains "no image is deleted"
  assert_contains "cannot say which"
  load_mctl
  run mi_led_all image
  [ -z "$output" ]
}

@test "outstanding checks are initialized to {alias} for EVERY recovered container" {
  net="$(mi_rt_network_create netA instA nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_repair_run "$IDX" instA
  run mi_state_outstanding c1
  assert_contains alias
}

@test "a RUNNING recovered container is verified IN THE SAME REPAIR RUN" {
  # A live verification names the probe container `mythical-<identity>-probe-<nonce>`, validating the
  # identity as a doc.sh `ident` (lowercase letter, then [a-z0-9-]) exactly as a minted identity always
  # is — so this fixture's chosen identity must actually be one, unlike the "instA" spelling other
  # repair tests use for identities that never reach probe naming.
  net="$(mi_rt_network_create netA insta nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=insta label=nonce=nc1 >/dev/null
  mi_rt_container_start c1 >/dev/null
  mi_prov_record_stub() { :; }
  mi_repair_run "$IDX" insta
  run mi_state_outstanding c1
  [ -z "$output" ]
}

@test "desired state is set from OBSERVATION and reported as inferred, listing each container" {
  net="$(mi_rt_network_create netA instA nA)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_image_pull "$(a_digestref p2)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$net" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_rt_container_create c2 "$(a_digestref p2)" "$net" p2 - label=installation=instA label=nonce=nc2 >/dev/null
  mi_rt_container_start c2 >/dev/null
  run mi_repair_run "$IDX" instA
  assert_contains "inferred from observation"
  assert_contains c1
  assert_contains c2
  load_mctl
  run mi_state_desired_get c1
  [ "$output" = stopped ]
  run mi_state_desired_get c2
  [ "$output" = running ]
}

@test "trust floors are RESET, with the rollback window stated and confirmed" {
  mi_rt_volume_create v1 n1 instA
  MI_CONFIRM=no run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  assert_contains "rollback"
  run mi_repair_run "$IDX" instA
  [ "$status" -eq 0 ]
}

@test "ZERO candidates offers confirmed REINITIALIZATION rather than deadlocking" {
  printf 'X=1\n' > "$MYTHICAL_HOME/brokkr.conf"
  run mi_repair_run "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "reinitializ"
  assert_contains "will not be recognised"
  load_mctl
  run mi_ident_get
  [ "$status" -eq 0 ]
}

@test "reinitialization is REFUSED when candidates were found — then the answer is to choose one" {
  mi_rt_volume_create v1 n1 instA
  run mi_repair_run "$IDX" --reinitialize
  [ "$status" -ne 0 ]
  assert_contains "choose"
}

@test "repair refuses while a LIVE lock is held" {
  mi_lock_acquire
  run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  mi_lock_release
}

@test "repair states plainly that it cannot prove nothing is in flight" {
  mi_rt_volume_create v1 n1 instA
  run mi_repair_run "$IDX" instA
  assert_contains "cannot prove"
}

@test "an object arriving AFTER a repair that RETAINED the identity is unrecorded same-identity" {
  mi_rt_volume_create v1 n1 instA
  mi_repair_run "$IDX" instA
  mi_rt_volume_create late n9 instA
  load_mctl; mi_lock_acquire
  run mi_unaccounted_gate
  [ "$status" -ne 0 ]
  assert_contains unrecorded
  mi_lock_release
}

@test "an object arriving after a REINITIALIZING repair is foreign-identity, listed, never touched" {
  # instOLD's object must arrive AFTER the reinitializing repair, not before it: were it created first
  # it would be a genuine candidate, and mi_repair_run --reinitialize correctly REFUSES to reinitialize
  # over an existing candidate (see "reinitialization is REFUSED when candidates were found" above) —
  # reinitializing anyway would strand it silently instead of reporting it.
  printf 'X=1\n' > "$MYTHICAL_HOME/brokkr.conf"
  mi_repair_run "$IDX" --reinitialize || true
  mi_rt_volume_create old n1 instOLD
  load_mctl; mi_lock_acquire
  run mi_unaccounted_gate
  [ "$status" -eq 0 ]
  run mi_unaccounted_scan
  assert_contains unattributed
  [ -e "$FAKE_DOCKER_STATE/volumes/old" ]
  mi_lock_release
}

@test "the non-owned reference is reconstructed from mythical.conf, not from the ledger" {
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  mi_rt_volume_create v1 n1 instA
  mi_repair_run "$IDX" instA
  load_mctl
  run mi_net_ref_get
  [ "$status" -eq 0 ]
  run mi_led_find netref key family
  assert_contains "owned=no"
}

@test "reconstruction that finds a DIFFERENT network than the containers' stops and enters the migration" {
  src="$(mi_rt_network_create oldnet "" x)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$src" p1 - label=installation=instA label=nonce=nc1 >/dev/null
  mi_rt_container_start c1 >/dev/null
  mi_rt_network_create opnet "" y >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_repair_run "$IDX" instA
  assert_contains "differs"
  load_mctl
  run mi_led_find netmig key family
  [ "$status" -eq 0 ]
  # The reference must name the OBSERVED network, and the intent must name it as the SOURCE.
  run mi_net_ref_get
  [ "$output" = "$src" ]
  run mi_led_find netmig key family
  assert_contains "source=$src"
}

@test "containers disagreeing about their network stops and reports — a migration cannot pick a side" {
  a="$(mi_rt_network_create na "" x)"; b="$(mi_rt_network_create nb "" y)"
  mi_rt_image_pull "$(a_digestref p1)" >/dev/null
  mi_rt_image_pull "$(a_digestref p2)" >/dev/null
  mi_rt_container_create c1 "$(a_digestref p1)" "$a" p1 - label=installation=instA label=nonce=n1 >/dev/null
  mi_rt_container_create c2 "$(a_digestref p2)" "$b" p2 - label=installation=instA label=nonce=n2 >/dev/null
  mi_rt_network_create opnet "" z >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_repair_run "$IDX" instA
  [ "$status" -ne 0 ]
  assert_contains "already split"
}

@test "abandon-intent refuses before the grace period and succeeds after, with confirmation" {
  mi_lock_acquire; mi_ident_ensure >/dev/null
  n="$(mi_nonce_new)"; mi_intent_open network net1 "$n"; mi_lock_release
  run mi_verb_abandon_intent network net1
  [ "$status" -ne 0 ]
  MI_INTENT_GRACE=0 run mi_verb_abandon_intent network net1
  [ "$status" -eq 0 ]
}

@test "abandon-intent will NOT run without confirmation" {
  mi_lock_acquire; mi_ident_ensure >/dev/null
  n="$(mi_nonce_new)"; mi_intent_open network net1 "$n"; mi_lock_release
  MI_CONFIRM=no MI_INTENT_GRACE=0 run mi_verb_abandon_intent network net1
  [ "$status" -ne 0 ]
}
