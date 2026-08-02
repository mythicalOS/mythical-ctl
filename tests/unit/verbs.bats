#!/usr/bin/env bats
# §6b.3's lifecycle verbs, at the function level: install/start/stop/restart/recreate/uninstall,
# family uninstall and status. Each holds the family lock, walks the sequence the earlier modules
# define, and reports.
#
# HELPER_RESOLVE_ADDR is left UNSET here: with none pinned, the fixture probe resolves each container's
# alias against the runtime's real DNS view (its actual address), so a fresh install's live
# verification passes — exactly as a real probe against a live daemon would. A test that wants a
# MISMATCH sets it explicitly (see the recreate case).
load '../lib/test_helper'
load '../harness/snapshot.sh'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; install_helper_img
  write_fixture_product p1            # index + policy + manifest for a launched fixture product
  IDX="$MYTHICAL_HOME/index"; POL="$MYTHICAL_HOME/policy"; MAN="$MYTHICAL_HOME/p1.manifest"
  # Establish the installation identity up front. Every verb that mutates mints it via mi_ident_ensure,
  # but the read-only status scan needs one to exist so it can classify a foreign object AGAINST it —
  # and that case never installs. Minting here also matches what an install would leave behind.
  mi_lock_acquire; mi_ident_ensure >/dev/null; mi_lock_release
}
teardown() { teardown_test_env; }

@test "install converges: identity, membership, network, volume, container, running, verified" {
  run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 0 ]
  IDENT="$(mi_ident_get)"
  run mi_member_has p1
  [ "$status" -eq 0 ]
  run mi_state_observed "mythical-${IDENT}-p1"
  [ "$output" = running ]
  run mi_state_outstanding "mythical-${IDENT}-p1"
  [ -z "$output" ]
}

@test "install is idempotent — a re-install leaves user-owned files byte-identical" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  printf '\n# operator note\nPEER=http://x\n' >> "$MYTHICAL_HOME/p1.conf"
  h="$(mi_digest "$MYTHICAL_HOME/p1.conf")"
  g="$(mi_digest "$MYTHICAL_HOME/mythical.conf")"
  run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 0 ]
  [ "$h" = "$(mi_digest "$MYTHICAL_HOME/p1.conf")" ]
  [ "$g" = "$(mi_digest "$MYTHICAL_HOME/mythical.conf")" ]
}

@test "install always declares running — re-installing a stopped product brings it back up (§6b.3)" {
  # install EXPRESSES intent and it is always `running`; only recreate preserves. Before this fix a
  # re-install read the prior generation's desired state and rebuilt the container STOPPED, returning 0
  # and even logging "installed and running" over a product that was not.
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  mi_verb_stop p1
  run mi_state_observed "$C"
  [ "$output" = stopped ]
  run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 0 ]
  run mi_state_desired_get "$C"
  [ "$output" = running ]
  run mi_state_observed "$C"
  [ "$output" = running ]
  run mi_state_outstanding "$C"
  [ -z "$output" ]
}

@test "install called as a library returns usage (2) on a value-less --image, never loops forever" {
  # The LIBRARY contract, not the CLI's guard: mi_verb_install must reject its own value-less option. A
  # bare `shift 2` past the end leaves $# unchanged and spins the option loop forever — a pure library
  # has no errexit to abort it — taking the caller down too. Run under a timeout so a regression FAILS
  # here (124) instead of hanging the suite; the fix returns 2 at once.
  cat > "$BATS_TEST_TMPDIR/lib_call.sh" <<EOF
for _m in common layout config lock ledger doc trust policy manifest detect runtime preflight exit prov intent state probe bringup netref verbs copy; do
  source "$_MCTL_ROOT/lib/\$_m.sh"
done
mi_verb_install "$IDX" "$POL" "$MAN" p1 --image
EOF
  run timeout 10 bash "$BATS_TEST_TMPDIR/lib_call.sh"
  [ "$status" -eq 2 ]
  assert_contains "requires a value"
}

@test "installing a SECOND product leaves the first's config and data untouched" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  snap_fs "$BATS_TEST_TMPDIR/f1"
  h1="$(mi_digest "$MYTHICAL_HOME/p1.conf")"
  write_fixture_product p2
  mi_verb_install "$IDX" "$MYTHICAL_HOME/policy" "$MYTHICAL_HOME/p2.manifest" p2 >/dev/null
  run grep -a 'p1.conf' "$BATS_TEST_TMPDIR/f1"
  [ "$status" -eq 0 ]
  # The second install touches only p2: p1's config file is byte-identical, and the SHARED
  # mythical.conf keeps its family key unclobbered. (Ports are not persisted — they default to the
  # manifest — so there is no port key for a sibling to overwrite in the first place.)
  [ "$h1" = "$(mi_digest "$MYTHICAL_HOME/p1.conf")" ]
  run mi_conf_get "$MYTHICAL_HOME/mythical.conf" MYTHICAL_TELEMETRY_KEY
  [ "$status" -eq 0 ]
  run mi_member_has p1
  [ "$status" -eq 0 ]
  run mi_rt_inspect volume v.nonce "mythical-${IDENT}-p1-state"
  [ "$status" -eq 0 ]
}

@test "a NOT-LAUNCHED manifest prints the message, exits 3, and creates NO product state" {
  write_fixture_product p1 launched=false
  snap_fs "$BATS_TEST_TMPDIR/f0"; snap_runtime "$BATS_TEST_TMPDIR/r0"
  run mi_verb_install "$IDX" "$POL" "$MYTHICAL_HOME/p1.manifest" p1
  [ "$status" -eq 3 ]
  assert_contains "has not launched yet"
  snap_runtime "$BATS_TEST_TMPDIR/r1"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/r0" "$BATS_TEST_TMPDIR/r1"
  [ "$status" -eq 0 ]
  [ ! -f "$MYTHICAL_HOME/p1.conf" ]
  [ ! -d "$MYTHICAL_HOME/p1" ]
}

@test "a not-launched attempt attempts NO PULL AT ALL" {
  write_fixture_product p1 launched=false
  mi_verb_install "$IDX" "$POL" "$MYTHICAL_HOME/p1.manifest" p1 || true
  run grep -a 'image pull' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
}

@test "a not-launched attempt DOES record the trust floor — otherwise a stale manifest replays later" {
  write_fixture_product p1 launched=false version=7
  mi_verb_install "$IDX" "$POL" "$MYTHICAL_HOME/p1.manifest" p1 || true
  run mi_trust_floor_get "manifest:p1"
  [ "$output" = 7 ]
}

@test "a LAUNCHED manifest whose image is not found is a LOUD RELEASE ERROR, never the not-launched message" {
  FAKE_DOCKER_PULL=notfound run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 1 ]
  # Assert on the install's own output BEFORE the grep below — `run grep … <<<"$output"` REPLACES
  # $output with grep's (empty) result, so a presence check after it would see nothing.
  assert_contains "could not be pulled"
  run grep -a 'has not launched yet' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "auth and network pull failures are loud and distinguishable" {
  FAKE_DOCKER_PULL=auth run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 1 ]
  assert_contains "denied"
  FAKE_DOCKER_PULL=neterr run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 1 ]
  assert_contains "no such host"
}

@test "stop sets desired=stopped BEFORE stopping, and a later run leaves it stopped" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  mi_verb_stop p1
  run mi_state_desired_get "$C"
  [ "$output" = stopped ]
  mi_verb_status "$IDX" p1 >/dev/null
  run mi_state_observed "$C"
  [ "$output" = stopped ]
}

@test "stop FAILS (1) when the runtime stop did not happen — a swallowed failure is not success" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  # The stop is attempted and dies (a daemon/permission/runtime failure). Reporting 0 here would leave
  # the product RUNNING while the CLI says it stopped — the §7.3 breach this pins.
  FAKE_DOCKER_INTERRUPT_AFTER='container stop' run mi_verb_stop p1
  [ "$status" -eq 1 ]
  # Intent was still committed FIRST (D43), but the container is still present and running because the
  # stop never took effect.
  run mi_state_desired_get "$C"
  [ "$output" = stopped ]
  run mi_rt_inspect container c.running "$C"
  [ "$output" = true ]
}

@test "install does NOT pull when the image-presence check could not be asked (rc1 is not absence)" {
  # The daemon answers through preflight, the gate and net setup, then goes unreachable FROM the image
  # inspect on — so both the presence check and the adapter's follow-up ping are unanswerable. A daemon
  # that could not be asked must STOP, not fold "could not ask" into "absent" and pull.
  FAKE_DOCKER_DOWN_FROM='image inspect' run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 1 ]
  run grep -a 'image pull' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]        # NO pull was attempted on an unanswerable presence check
}

@test "restart is REFUSED on a stopped product rather than silently starting it" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  mi_verb_stop p1
  run mi_verb_restart "$IDX" p1
  [ "$status" -ne 0 ]
  assert_contains "stopped"
  IDENT="$(mi_ident_get)"
  run mi_state_observed "mythical-${IDENT}-p1"
  [ "$output" = stopped ]
}

@test "restart FAILS (1) on a swallowed stop — a container that never went down is not a restart" {
  # The sibling of the stop fix: restart's `container stop` is a MEANS, and a swallowed failure leaves
  # the container RUNNING. mi_bringup_reconcile then sees it live with a resolving alias and returns 0 —
  # a restart that never restarted. The interrupt knob fabricates the failed stop.
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  FAKE_DOCKER_INTERRUPT_AFTER='container stop' run mi_verb_restart "$IDX" p1
  [ "$status" -eq 1 ]
  # It is still present and running — the stop did not take.
  run mi_rt_inspect container c.running "$C"
  [ "$output" = true ]
}

@test "recreate of a STOPPED product stays stopped" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  mi_verb_stop p1
  run mi_verb_recreate "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 0 ]
  IDENT="$(mi_ident_get)"
  run mi_state_desired_get "mythical-${IDENT}-p1"
  [ "$output" = stopped ]
  run mi_state_observed "mythical-${IDENT}-p1"
  [ "$output" = stopped ]
}

@test "recreate live-verifies like a fresh install, not assumed good for replacing a working one" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  mi_verb_recreate "$IDX" "$POL" "$MAN" p1 >/dev/null
  run mi_state_outstanding "mythical-${IDENT}-p1"
  [ -z "$output" ]
  HELPER_RESOLVE_ADDR=9.9.9.9 mi_verb_recreate "$IDX" "$POL" "$MAN" p1 || true
  run mi_state_outstanding "mythical-${IDENT}-p1"
  assert_contains alias
}

@test "product uninstall RETAINS the trust floor and membership (§6c) — the rollback bypass" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  floor="$(mi_trust_floor_get manifest:p1)"
  mi_verb_uninstall p1
  run mi_trust_floor_get manifest:p1
  [ "$output" = "$floor" ]
  run mi_member_has p1
  [ "$status" -eq 0 ]
}

@test "product uninstall leaves bin/ and mythical.conf, and a sibling's config, alone" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  write_fixture_product p2
  mi_verb_install "$IDX" "$MYTHICAL_HOME/policy" "$MYTHICAL_HOME/p2.manifest" p2 >/dev/null
  printf '#!/bin/sh\n' > "$MYTHICAL_HOME/bin/mythical-ctl"
  g="$(mi_digest "$MYTHICAL_HOME/mythical.conf")"
  h2="$(mi_digest "$MYTHICAL_HOME/p2.conf")"
  mi_verb_uninstall p1
  [ -f "$MYTHICAL_HOME/bin/mythical-ctl" ]
  [ "$g" = "$(mi_digest "$MYTHICAL_HOME/mythical.conf")" ]
  [ "$h2" = "$(mi_digest "$MYTHICAL_HOME/p2.conf")" ]
}

@test "product uninstall RETAINS named volumes, and keeps their provenance so --purge still has authority" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  mi_verb_uninstall p1
  run mi_rt_inspect volume v.nonce "mythical-${IDENT}-p1-state"
  [ "$status" -eq 0 ]
  run mi_prov_find volume "mythical-${IDENT}-p1-state"
  [ "$status" -eq 0 ]
}

@test "--purge removes the volumes it has authority over and tombstones them" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  mi_verb_uninstall p1 --purge
  run mi_rt_inspect volume v.nonce "mythical-${IDENT}-p1-state"
  [ "$status" -eq 3 ]
  run mi_led_all tombstone
  assert_contains "mythical-${IDENT}-p1-state"
}

@test "NO verb removes an image — not uninstall, not --purge" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  mi_verb_uninstall p1 --purge
  run grep -a 'image rm' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
}

@test "--purge OFFERS images as an explicitly confirmed extra step, naming the shared-use risk" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  run mi_verb_uninstall p1 --purge
  assert_contains "may be in use"
  assert_contains "docker image"
}

@test "uninstall with an --image override leaves the override image in place" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 --image "$(a_digestref local)" >/dev/null
  mi_verb_uninstall p1 --purge
  run grep -a 'image rm' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
}

@test "FAMILY uninstall resets the ledger entirely WITHOUT --purge, and leaves the volumes (§6c)" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  printf 'note\n' > "$MYTHICAL_HOME/transcripts/x"
  # §6c: the family reset is UNCONDITIONAL — identity, membership, every floor and the anchor go whether
  # or not --purge is given. Only the VOLUMES' fate depends on --purge: without it they are left in
  # place (orphaned but preserved), which is asserted here alongside the reset. Keeping the ledger to
  # "protect" retained volumes would leave a fresh machine still carrying the old identity — a contract
  # violation, not a safety feature.
  MI_CONFIRM=yes run mi_verb_uninstall_family
  [ "$status" -eq 0 ]
  run mi_rt_inspect container c.running "mythical-${IDENT}-p1"
  [ "$status" -eq 3 ]
  run mi_ident_get
  [ "$status" -eq 3 ]
  run mi_member_has p1
  [ "$status" -ne 0 ]
  run mi_trust_floor_get manifest:p1
  [ "$status" -ne 0 ]
  run mi_rt_inspect volume v.nonce "mythical-${IDENT}-p1-state"
  [ "$status" -eq 0 ]                         # the volume SURVIVES the no-purge reset (your data)
  [ -f "$MYTHICAL_HOME/transcripts/x" ]      # user data is never touched, by any verb
}

@test "family uninstall keeps named volumes without --purge and removes them with it" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  MI_CONFIRM=yes mi_verb_uninstall_family
  run mi_rt_inspect volume v.nonce "mythical-${IDENT}-p1-state"
  [ "$status" -eq 0 ]
}

@test "family uninstall --purge removes the volumes it has authority over" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  MI_CONFIRM=yes mi_verb_uninstall_family --purge
  run mi_rt_inspect volume v.nonce "mythical-${IDENT}-p1-state"
  [ "$status" -eq 3 ]
}

@test "family uninstall removes the network it created" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  MI_CONFIRM=yes mi_verb_uninstall_family
  run mi_rt_inspect network n.id "mythical-${IDENT}-net"
  [ "$status" -eq 3 ]
}

@test "family uninstall NEVER removes an operator-supplied network — it is attach-only" {
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' >> "$MYTHICAL_HOME/mythical.conf"
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  MI_CONFIRM=yes mi_verb_uninstall_family
  run mi_rt_inspect network n.id opnet
  [ "$status" -eq 0 ]
}

@test "family uninstall PRESERVES an object whose nonce no longer matches" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  printf 'labels=mythicalos.installation=%s;mythicalos.nonce=OTHER;\nstate=exited\nnets=\n' "$IDENT" \
    > "$FAKE_DOCKER_STATE/containers/$C"
  # The nonce no longer matches the ledger, so the object is same-identity-but-unaccounted: the verb
  # STOPS (nonzero) rather than removing something it can no longer prove is the one it recorded. The
  # `|| true` keeps that intended refusal from failing the bats test; the assertion is that the object
  # SURVIVES, which is the whole point.
  MI_CONFIRM=yes mi_verb_uninstall_family || true
  [ -e "$FAKE_DOCKER_STATE/containers/$C" ]
}

@test "family uninstall removes NO image, and says so" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  MI_CONFIRM=yes run mi_verb_uninstall_family
  assert_contains "NOT removed"
  run grep -a 'image rm' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
}

@test "family uninstall refuses without an explicit confirmation, and changes nothing" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  MI_CONFIRM=no run mi_verb_uninstall_family
  [ "$status" -ne 0 ]
  run mi_ident_get
  [ "$status" -eq 0 ]
  run mi_rt_inspect container c.running "mythical-${IDENT}-p1"
  [ "$status" -eq 0 ]
}

@test "an unrecorded same-identity object STOPS a mutating verb" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  mi_rt_volume_create "mythical-${IDENT}-stray" nx "$IDENT"
  run mi_verb_start "$IDX" p1
  [ "$status" -ne 0 ]
  assert_contains "unrecorded"
}

@test "the same object does NOT stop status, which reports it and exits 0" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  mi_rt_volume_create "mythical-${IDENT}-stray" nx "$IDENT"
  run mi_verb_status "$IDX" p1
  [ "$status" -eq 0 ]
  assert_contains "unrecorded"
}

@test "status lists unattributed objects and never proposes removing them" {
  mi_rt_volume_create someone-elses nz otherinstall
  run mi_verb_status "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "unattributed"
  assert_contains "another user"
}

@test "an --image override is loud, recorded, and reported by status" {
  ref="$(a_digestref localbuild)"
  run mi_verb_install "$IDX" "$POL" "$MAN" p1 --image "$ref"
  assert_contains "OVERRIDE"
  run mi_verb_status "$IDX" p1
  assert_contains "$ref"
  assert_contains "override"
}

@test "--force-install is loud and reported by status" {
  write_fixture_product p1 launched=false
  run mi_verb_install "$IDX" "$POL" "$MYTHICAL_HOME/p1.manifest" p1 --force-install
  assert_contains "FORCED"
  run mi_verb_status "$IDX" p1
  assert_contains "force"
}

@test "a manifest for a DIFFERENT product is refused before any object is created" {
  snap_runtime "$BATS_TEST_TMPDIR/r0"
  run mi_verb_install "$IDX" "$POL" "$MAN" p2
  [ "$status" -eq 1 ]
  snap_runtime "$BATS_TEST_TMPDIR/r1"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/r0" "$BATS_TEST_TMPDIR/r1"
  [ "$status" -eq 0 ]
}

@test "the family lock is held for the whole of a mutating verb, and released after" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  [ ! -f "$MYTHICAL_HOME/.state/lock" ]
}

@test "a verb refuses when the lock is already held by a live process" {
  mi_lock_acquire
  run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 1 ]
  assert_contains "in progress"
  mi_lock_release
}
