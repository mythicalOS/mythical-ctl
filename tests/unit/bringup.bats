#!/usr/bin/env bats
# §6b.3 — the ordered bring-up sequence, where every earlier module meets.
#
# The order is FIXED and confirmation comes LAST, so "confirmed" always means "attached correctly, and
# to nothing else": create stopped and attached at creation · verify the COMPLETE network set · record
# desired state, set the outstanding check and confirm · start · verify live, then clear.
load '../lib/test_helper'
load '../harness/snapshot.sh'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; mi_lock_acquire; install_helper_img
  IDENT="$(mi_ident_ensure)"
  NET="$(mi_rt_network_create "mythical-${IDENT}-net" "$IDENT" nnet)"
  C="mythical-${IDENT}-p1"
  IMG="$(a_digestref p1)"
  # `container create` refuses an image that was never pulled, exactly as a real daemon does.
  mi_rt_image_pull "$IMG" >/dev/null
  write_index_fixture "$MYTHICAL_HOME/index"
  IDX="$MYTHICAL_HOME/index"
  # WHAT THE ALIAS MUST RESOLVE TO for a live verification to pass. Step 5 compares the probe's answer
  # against the address the container ACTUALLY has, so a fixture that leaves the probe's canned answer
  # in place is asserting a mismatch, not a happy path. The address is asked of the runtime rather
  # than re-derived here: a second copy of the fake's derivation would drift from it silently.
  ADDR="$(learn_addr "$C" "$NET")"
  HELPER_RESOLVE_ADDR="$ADDR"; export HELPER_RESOLVE_ADDR
}
teardown() { mi_lock_release; teardown_test_env; }

# The address <container> will be given on <netid> once it is started. Deterministic per pair, so a
# throwaway create+start answers it and is removed again.
learn_addr() {
  local n="$1" net="$2" nets
  mi_rt_container_create "$n" "$IMG" "$net" learnaddr - >/dev/null
  mi_rt_container_start "$n" >/dev/null
  nets="$(mi_rt_inspect container c.nets "$n")"
  mi_rt_container_rm "$n" >/dev/null
  nets="${nets%;}"
  printf '%s\n' "${nets#*=}"
}

@test "bring-up creates STOPPED, on exactly the target network, with the alias" {
  mi_bringup_create "$C" "$IMG" "$NET" p1 running - >/dev/null
  run mi_rt_inspect container c.running "$C"
  [ "$output" = false ]
  run mi_bringup_verify_attach "$C" "$NET" p1
  [ "$status" -eq 0 ]
}

@test "attachment verification asserts the network set is EXACTLY the expected ID" {
  mi_bringup_create "$C" "$IMG" "$NET" p1 running - >/dev/null
  OTHER="$(mi_rt_network_create other "$IDENT" nn2)"
  mi_rt_network_connect "$OTHER" "$C" p1 0
  run mi_bringup_verify_attach "$C" "$NET" p1
  [ "$status" -ne 0 ]
  assert_contains "exactly"
}

@test "a container attached to NOTHING fails verification, and says so" {
  mi_bringup_create "$C" "$IMG" "$NET" p1 running - >/dev/null
  mi_rt_network_disconnect "$NET" "$C"
  run mi_bringup_verify_attach "$C" "$NET" p1
  [ "$status" -ne 0 ]
  assert_contains "NO network"
}

@test "a container on TWO networks WITH a recorded migration intent is permitted, bounded to {old,new}" {
  mi_bringup_create "$C" "$IMG" "$NET" p1 running - >/dev/null
  OTHER="$(mi_rt_network_create other "$IDENT" nn2)"
  mi_rt_network_connect "$OTHER" "$C" p1 0
  mi_led_put netmig key family "key=family" "phase=2" "source=$NET" "target=$OTHER" "containers=$C"
  run mi_bringup_verify_attach "$C" "$OTHER" p1
  [ "$status" -eq 0 ]
}

@test "a container on a THIRD network is a failure even during a migration" {
  mi_bringup_create "$C" "$IMG" "$NET" p1 running - >/dev/null
  O2="$(mi_rt_network_create other2 "$IDENT" nn2)"
  O3="$(mi_rt_network_create other3 "$IDENT" nn3)"
  mi_rt_network_connect "$O2" "$C" p1 0
  mi_rt_network_connect "$O3" "$C" p1 0
  mi_led_put netmig key family "key=family" "phase=2" "source=$NET" "target=$O2" "containers=$C"
  run mi_bringup_verify_attach "$C" "$O2" p1
  [ "$status" -ne 0 ]
}

# Both directions of the set comparison. The loop above catches a STRAY attachment; this catches a
# container sitting on the migration's SOURCE only, which every "is anything unexpected here" test
# passes.
@test "a container attached only to the migration's SOURCE fails verification against the TARGET" {
  mi_bringup_create "$C" "$IMG" "$NET" p1 running - >/dev/null
  OTHER="$(mi_rt_network_create other "$IDENT" nn2)"
  mi_led_put netmig key family "key=family" "phase=2" "source=$NET" "target=$OTHER" "containers=$C"
  run mi_bringup_verify_attach "$C" "$OTHER" p1
  [ "$status" -ne 0 ]
  assert_contains "not attached to the expected network"
}

@test "a missing ALIAS fails verification even when the attachment is right" {
  mi_bringup_create "$C" "$IMG" "$NET" wrongalias running - >/dev/null
  run mi_bringup_verify_attach "$C" "$NET" p1
  [ "$status" -ne 0 ]
  assert_contains "alias"
}

@test "the full bring-up sets the outstanding entry at CONFIRM and clears it only after live verify" {
  run mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running -
  [ "$status" -eq 0 ]
  run mi_state_desired_get "$C"
  [ "$output" = running ]
  run mi_state_outstanding "$C"
  [ -z "$output" ]
  run mi_state_observed "$C"
  [ "$output" = running ]
  # And the object is accounted for: a clean run ends with provenance, not with an open intent.
  run mi_prov_find container "$C"
  [ "$status" -eq 0 ]
  run mi_intent_find container "$C"
  [ "$status" -eq 3 ]
}

@test "a FRESH install live-verifies the alias — the flag exists and the commonest path sets it" {
  HELPER_RESOLVE_ADDR=1.2.3.4 run mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running -
  [ "$status" -ne 0 ]
  assert_contains "resolves to '1.2.3.4'"
  run mi_state_outstanding "$C"
  assert_contains alias
}

@test "live verification FAILING leaves the product RUNNING and keeps the entry" {
  HELPER_RESOLVE_ADDR= mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running - || true
  run mi_state_observed "$C"
  [ "$output" = running ]
  run mi_state_outstanding "$C"
  assert_contains alias
}

# A verification that could not be PERFORMED is not a verification that failed, and neither of them
# retires the check. The probe is made unrunnable at the daemon.
@test "a probe that could not run leaves the entry outstanding and says the check was not made" {
  FAKE_DOCKER_HELPER_FAIL=boom run mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running -
  [ "$status" -ne 0 ]
  assert_contains "probe could not run"
  run mi_state_outstanding "$C"
  assert_contains alias
  run mi_state_observed "$C"
  [ "$output" = running ]
}

@test "desired state is a PARAMETER — a replacement preserves stopped" {
  mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running - >/dev/null
  mi_state_commit "$C" stopped
  mi_rt_container_stop "$C" >/dev/null
  mi_rt_container_rm "$C" >/dev/null
  run mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 preserve -
  [ "$status" -eq 0 ]
  run mi_state_desired_get "$C"
  [ "$output" = stopped ]
  run mi_state_observed "$C"
  [ "$output" = stopped ]
}

@test "preserve with NOTHING recorded is a usage error, not a silent running" {
  run mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 preserve -
  [ "$status" -ne 0 ]
  assert_contains "no desired state"
}

# A `stopped` bring-up has no address for its alias to answer with, so the check is DEFERRED — which
# is not skipping. Clearing it here would report a verification nobody performed.
@test "a stopped bring-up keeps the outstanding entry rather than clearing or performing it" {
  run mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 stopped -
  [ "$status" -eq 0 ]
  run mi_state_observed "$C"
  [ "$output" = stopped ]
  run mi_state_outstanding "$C"
  assert_contains alias
}

@test "the live address is read by RE-INSPECTING after the start" {
  mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running - >/dev/null
  addr="$(mi_rt_inspect container c.nets "$C")"
  [ "$addr" != "${NET}=;" ]
}

# CONFIRMATION COMES LAST. A bring-up whose topology does not verify must leave nothing behind that
# says the object was built — no provenance, no desired state, and no container. The topology is made
# unacceptable by recording a migration between two OTHER networks, which bounds the permitted set to
# a pair this container is not in.
@test "a bring-up that does not verify confirms NOTHING and removes the container" {
  O1="$(mi_rt_network_create o1 "$IDENT" n1)"
  O2="$(mi_rt_network_create o2 "$IDENT" n2)"
  mi_led_put netmig key family "key=family" "phase=2" "source=$O1" "target=$O2"
  run mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running -
  [ "$status" -ne 0 ]
  assert_contains "removed"
  run mi_prov_find container "$C"
  [ "$status" -eq 3 ]
  run mi_state_desired_get "$C"
  [ "$status" -eq 3 ]
  run mi_rt_inspect container c.running "$C"
  [ "$status" -eq 3 ]
}

# A CONFIRMED CONTAINER MUST BE ONE THE RECONCILER CAN STILL ACT ON. Recovery used to confirm and stop
# there: the intent — the only record of what was being built — was consumed, no desired state and no
# outstanding check were ever written, and mi_state_plan then answered `none` for ever. The container
# was never started and never live-verified, and no entry existed for a later start to schedule the
# verification from. So the plan is asserted here, not just the provenance: `none` is precisely the
# answer the defect produced, and it is indistinguishable from a healthy reconciled container.
@test "recovery from a crash after CREATE establishes desired state and the check, then confirms" {
  mi_bringup_create "$C" "$IMG" "$NET" p1 running - >/dev/null
  run mi_bringup_recover "$IDX" "$C" "$NET" p1
  [ "$status" -eq 0 ]
  run mi_prov_find container "$C"
  [ "$status" -eq 0 ]
  run mi_intent_find container "$C"
  [ "$status" -eq 3 ]
  run mi_state_desired_get "$C"
  [ "$output" = running ]
  run mi_state_outstanding "$C"
  assert_contains alias
  run mi_state_plan "$C"
  [ "$output" = "start verify" ]
}

# The desired state is the one thing the dying process knew and nothing else does, so it has to survive
# in the intent rather than be re-derived. A bring-up the operator asked to leave STOPPED must not come
# back as `running`.
@test "recovery restores the desired state the bring-up recorded, not a default" {
  mi_bringup_create "$C" "$IMG" "$NET" p1 stopped - >/dev/null
  run mi_bringup_recover "$IDX" "$C" "$NET" p1
  [ "$status" -eq 0 ]
  run mi_state_desired_get "$C"
  [ "$output" = stopped ]
  run mi_state_plan "$C"
  [ "$output" = defer ]
  run mi_rt_inspect container c.running "$C"
  [ "$output" = false ]
}

# An intent that does not say what it was in the middle of DOING cannot be finished, and confirming it
# anyway is the quiet form of the defect above. Both the container and the intent survive.
@test "recovery refuses an intent that does not record what the bring-up was doing" {
  n="$(mi_nonce_new)"
  mi_intent_open container "$C" "$n" "product=p1"
  mi_rt_container_create "$C" "$IMG" "$NET" p1 - label=installation="$IDENT" label=nonce="$n" >/dev/null
  run mi_bringup_recover "$IDX" "$C" "$NET" p1
  [ "$status" -eq 1 ]
  assert_contains "does not say which desired state"
  run mi_prov_find container "$C"
  [ "$status" -eq 3 ]
  run mi_intent_find container "$C"
  [ "$status" -eq 0 ]
  run mi_rt_inspect container c.running "$C"
  [ "$status" -eq 0 ]
}

# The topology is verified against the caller's network and the check is recorded from the intent's, so
# a disagreement would record a check for a network nothing looked at. Neither is preferred over the
# other; both are preserved.
@test "recovery refuses when the intent names a different network from the one it is asked about" {
  OTHER="$(mi_rt_network_create other "$IDENT" nn2)"
  mi_bringup_create "$C" "$IMG" "$NET" p1 running - >/dev/null
  run mi_bringup_recover "$IDX" "$C" "$OTHER" p1
  [ "$status" -eq 1 ]
  assert_contains "two different bring-ups"
  run mi_prov_find container "$C"
  [ "$status" -eq 3 ]
  run mi_intent_find container "$C"
  [ "$status" -eq 0 ]
  run mi_rt_inspect container c.running "$C"
  [ "$status" -eq 0 ]
}

@test "recovery from a crash after CREATE with a WRONG topology removes and reissues" {
  mi_bringup_create "$C" "$IMG" "$NET" p1 running - >/dev/null
  BAD="$(mi_rt_network_create bad "$IDENT" nb)"
  mi_rt_network_connect "$BAD" "$C" p1 0
  run mi_bringup_recover "$IDX" "$C" "$NET" p1
  [ "$status" -eq 4 ]
  assert_contains "removed"
  run mi_rt_inspect container c.running "$C"
  [ "$status" -eq 3 ]
  # Nothing was confirmed on the way out, and the intent is RETAINED for the verb to rebuild from.
  run mi_prov_find container "$C"
  [ "$status" -eq 3 ]
  run mi_intent_find container "$C"
  [ "$status" -eq 0 ]
  # And no desired state was recorded for a container that was just removed.
  run mi_state_desired_get "$C"
  [ "$status" -eq 3 ]
}

@test "recovery refuses a container standing at the name under a DIFFERENT nonce" {
  mi_bringup_create "$C" "$IMG" "$NET" p1 running - >/dev/null
  mi_rt_container_rm "$C" >/dev/null
  mi_rt_container_create "$C" "$IMG" "$NET" p1 - label=installation="$IDENT" label=nonce=someoneelse >/dev/null
  run mi_bringup_recover "$IDX" "$C" "$NET" p1
  [ "$status" -eq 1 ]
  assert_contains "NOT adopted"
  run mi_rt_inspect container c.running "$C"
  [ "$status" -eq 0 ]
  run mi_state_desired_get "$C"
  [ "$status" -eq 3 ]
}

# The cross-task obligation: a verb performing a `start verify` plan RECORDS the resume before it
# starts, so the attempt is on the ledger and the next plan cannot be a second start. Without the
# record neither the desired state nor the outstanding set changes when a container exits at once,
# so the plan would be identical for ever.
@test "a resume is attempted ONCE per run and recorded — never a restart loop" {
  mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running - >/dev/null
  mi_rt_container_stop "$C" >/dev/null
  run mi_state_plan "$C"
  [ "$output" = "start verify" ]
  # The resume happens: it IS started, and its live verification does not pass — so nothing reports
  # that the container came up and nothing retires the attempt record.
  HELPER_RESOLVE_ADDR=1.2.3.4 run mi_bringup_reconcile "$IDX" "$C" "$NET" p1
  [ "$status" -ne 0 ]
  run mi_rt_inspect container c.running "$C"
  [ "$output" = true ]
  run mi_led_find resumed container "$C"
  [ "$status" -eq 0 ]

  # It does not stay up. The SECOND pass must report it, not start it a second time — which is the
  # whole difference the attempt record makes, and it is the caller's to record.
  mi_rt_container_stop "$C" >/dev/null
  run mi_state_plan "$C"
  [ "$output" = exited ]
  run mi_bringup_reconcile "$IDX" "$C" "$NET" p1
  [ "$status" -ne 0 ]
  assert_contains "ALREADY resumed"
  run mi_rt_inspect container c.running "$C"
  [ "$output" = false ]
}

# STEP 5 IS THE STEP THAT CLEARS, so every property "confirmed" claims has to hold at that moment —
# including the one about what the container is NOT attached to. The topology changes here BETWEEN the
# attachment check and the clear, which nothing covered: the alias still resolves to the target
# network's address, because aliases are network-scoped and that endpoint is untouched, so the live
# check passed and retired the only outstanding entry on a container sitting on an extra network.
#
# The address is left correct on purpose. A test that also broke resolution would go red for the
# ordinary reason and prove nothing about the set check.
@test "the live check refuses to clear while the container has gained an EXTRA network" {
  HELPER_RESOLVE_ADDR=1.2.3.4 mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running - || true
  # The precondition: there IS a check to lose. Without this the assertions below hold just as well
  # for a bring-up that never recorded one.
  run mi_state_outstanding "$C"
  assert_contains alias
  OTHER="$(mi_rt_network_create other "$IDENT" nn2)"
  mi_rt_network_connect "$OTHER" "$C" p1 0
  # The alias now resolves correctly — the reconcile fails on the SET, not on the address.
  HELPER_RESOLVE_ADDR="$ADDR" run mi_bringup_reconcile "$IDX" "$C" "$NET" p1
  [ "$status" -ne 0 ]
  assert_contains "not permitted"
  run mi_state_outstanding "$C"
  assert_contains alias
  # And the product is LEFT RUNNING — a failed verification is a state, not a reason to stop it.
  run mi_rt_inspect container c.running "$C"
  [ "$output" = true ]
}

# The same rule, at the function itself, with the resolution provably working: `selfcheck` and the
# address comparison both succeed, so the only thing that can refuse is the complete-set check.
@test "live verification asks the COMPLETE set, not just the address on the target network" {
  mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running - >/dev/null
  run mi_bringup_verify_live "$IDX" "$C" "$NET" p1
  [ "$status" -eq 0 ]
  OTHER="$(mi_rt_network_create other "$IDENT" nn2)"
  mi_rt_network_connect "$OTHER" "$C" p1 0
  run mi_bringup_verify_live "$IDX" "$C" "$NET" p1
  [ "$status" -eq 1 ]
  assert_contains "not permitted"
}

@test "a running container with an outstanding check is verified NOW, and the entry then clears" {
  HELPER_RESOLVE_ADDR=1.2.3.4 mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running - || true
  run mi_state_plan "$C"
  [ "$output" = verify ]
  run mi_bringup_reconcile "$IDX" "$C" "$NET" p1
  [ "$status" -eq 0 ]
  run mi_state_outstanding "$C"
  [ -z "$output" ]
}

@test "a stopped container with an outstanding check is deferred, never cleared" {
  run mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 stopped -
  [ "$status" -eq 0 ]
  run mi_state_plan "$C"
  [ "$output" = defer ]
  run mi_bringup_reconcile "$IDX" "$C" "$NET" p1
  [ "$status" -eq 0 ]
  assert_contains "next start"
  run mi_state_outstanding "$C"
  assert_contains alias
}

@test "no product state survives a failed bring-up beyond what was recorded ahead of it" {
  snap_fs "$BATS_TEST_TMPDIR/f0"; snap_runtime "$BATS_TEST_TMPDIR/r0"
  run mi_bringup "$IDX" "$C" "$IMG" host p1 running -
  [ "$status" -ne 0 ]
  snap_runtime "$BATS_TEST_TMPDIR/r1"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/r0" "$BATS_TEST_TMPDIR/r1"
  [ "$status" -eq 0 ]
}

@test "the secret env file holds ONLY the product's declared keys, is 0600, and outlives the call" {
  printf 'MYTHICAL_TELEMETRY_KEY=tk\nMYTHICAL_NET=n\n' > "$MYTHICAL_HOME/mythical.conf"
  f="$(mi_secrets_envfile p1 MYTHICAL_TELEMETRY_KEY)"
  [ -f "$f" ]
  [ "$(ls -l "$f" | cut -c1-10)" = "-rw-------" ]
  run grep -ac . "$f"
  [ "$output" = 1 ]
  run grep -a 'MYTHICAL_TELEMETRY_KEY=tk' "$f"
  [ "$status" -eq 0 ]
  run grep -a 'MYTHICAL_NET' "$f"
  [ "$status" -ne 0 ]
}

@test "a secret the product is not entitled to is REFUSED, not silently dropped" {
  printf 'MYTHICAL_TELEMETRY_KEY=tk\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_secrets_envfile p1 MYTHICAL_REGISTRY_TOKEN
  [ "$status" -ne 0 ]
}

# A declared key with no value is a missing bootstrap secret, not an empty one — and the half-written
# file must not survive the refusal.
@test "a declared secret that is not set REFUSES and leaves no file behind" {
  printf 'MYTHICAL_NET=n\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_secrets_envfile p1 MYTHICAL_TELEMETRY_KEY
  [ "$status" -ne 0 ]
  assert_contains "not set"
  run ls -a "$MYTHICAL_HOME/.state"
  case "$output" in
    *.env.p1.*) echo "a refused secret file was left on disk: $output" >&2; return 1 ;;
  esac
}

@test "no value from <product>.conf reaches any launch argument" {
  printf 'PEER=--privileged\n#mythical-conf-sha256=x\n' > "$MYTHICAL_HOME/p1.conf"
  mi_bringup "$IDX" "$C" "$IMG" "$NET" p1 running - >/dev/null || true
  # The launch HAPPENED — without this the assertion below would hold just as well for a bring-up
  # that never ran at all. The alias is what distinguishes it from the throwaway create in setup.
  run grep -a -- "--network-alias p1" "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
  run grep -a -- '--privileged' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
}
