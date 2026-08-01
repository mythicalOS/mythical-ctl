#!/usr/bin/env bats
# D41/D44/D45 — which network the family joins, and how it is ever changed.
#
# Two subjects. The NON-OWNED REFERENCE: an operator-supplied network is configured by name, is
# deliberately unlabelled, and is not ours to remove — so it is resolved uniquely, persisted
# attach-only with no deletion authority, and re-verified before use. And the PHASED REBIND: recording
# a new network id while already-installed containers stay on the old one splits family DNS silently,
# with every product reporting healthy, so the fleet moves in ordered phases and the phase is recorded
# before it is entered.
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; mi_lock_acquire; install_helper_img
  IDENT="$(mi_ident_ensure)"
  write_index_fixture "$MYTHICAL_HOME/index"; IDX="$MYTHICAL_HOME/index"
}
teardown() { mi_lock_release; teardown_test_env; }

# --- fixtures --------------------------------------------------------------------------------------

# A product container of this installation on <netid>, recorded in provenance and given a desired
# state. `running` starts it; anything else leaves it created (which the runtime reports as stopped,
# with NO endpoint address — the property D48 turns on).
#
# The image is PULLED first: `container create` refuses one that was never pulled, exactly as a real
# daemon does. The alias is the one lib/manifest.sh derives, because that is the name phase 2 will
# register on the target and the name a sibling actually resolves.
a_sibling() {
  local p="$1" net="$2" want="${3:-running}" c img
  c="mythical-${IDENT}-${p}"
  img="$(a_digestref "$p")"
  mi_rt_image_pull "$img" >/dev/null
  mi_rt_container_create "$c" "$img" "$net" "$(mi_name_alias "$p")" - \
    "label=installation=${IDENT}" "label=nonce=n${p}" >/dev/null
  mi_prov_record container "$c" "n${p}" "product=${p}"
  if [ "$want" = running ]; then
    mi_rt_container_start "$c" >/dev/null
    # `+none` is not decoration: a `running` commit that would leave nothing outstanding and declares
    # nothing is refused, because an empty outstanding set is exactly what a crash between recording
    # the intent and recording the check leaves behind.
    mi_state_commit "$c" running +none
  else
    mi_state_commit "$c" stopped
  fi
  printf '%s\n' "$c"
}

# The address <container> holds on <netid>, out of the runtime's own answer. Walked one separator at a
# time with parameter expansion: an unquoted IFS split would also glob, and an attachment whose value
# happened to be a pattern would be replaced by matching filenames.
addr_on() {
  local c="$1" net="$2" rest pair
  rest="$(mi_rt_inspect container c.nets "$c")" || return 1
  while [ -n "$rest" ]; do
    pair="${rest%%;*}"
    if [ "$rest" = "$pair" ]; then rest=""; else rest="${rest#*;}"; fi
    case "$pair" in "${net}="*) printf '%s\n' "${pair#*=}"; return 0 ;; esac
  done
  return 1
}

# The address <container> WILL hold on <netid> once it is attached, for a fixture that must know it
# before the code under test attaches anything. The fake assigns a deterministic address per
# (container, network), so attaching, reading and detaching answers it — rather than a second copy of
# the fake's derivation here, which would drift from it silently.
addr_will_be() {
  local c="$1" net="$2" a
  mi_rt_network_connect "$net" "$c" learnaddr 0 >/dev/null
  a="$(addr_on "$c" "$net")" || return 1
  mi_rt_network_disconnect "$net" "$c" >/dev/null
  printf '%s\n' "$a"
}

# What the probe will answer when asked for a sibling's alias. Step 5 compares the answer against the
# address the container ACTUALLY has, so a fixture that leaves the canned answer in place is asserting
# a mismatch rather than a happy path.
probe_answers() { HELPER_RESOLVE_ADDR="$1"; export HELPER_RESOLVE_ADDR; }

# --- the two sources of a network id ---------------------------------------------------------------

@test "with no MYTHICAL_NET the core creates and OWNS an installation-scoped network" {
  id="$(mi_net_target "$IDX")"
  [ -n "$id" ]
  run mi_prov_find network "$(mi_name_network "$IDENT")"
  [ "$status" -eq 0 ]
  run mi_net_ref_get
  [ "$status" -eq 3 ]
}

@test "an owned network is created only once — a second call adopts the recorded one" {
  a="$(mi_net_target "$IDX")"
  b="$(mi_net_target "$IDX")"
  [ "$a" = "$b" ]
  run mi_rt_find_by_label network installation "$IDENT"
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 1 ]
}

@test "a recorded owned network that no longer resolves is NOT recreated over" {
  mi_net_target "$IDX" >/dev/null
  mi_rt_network_rm "$(mi_name_network "$IDENT")" >/dev/null
  run mi_net_target "$IDX"
  [ "$status" -ne 0 ]
  assert_contains "state repair"
  run mi_rt_find_by_label network installation "$IDENT"
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 0 ]
}

@test "an operator-supplied network is resolved to an ID and marked attach-only" {
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  id="$(mi_net_target "$IDX")"
  run mi_net_ref_get
  [ "$output" = "$id" ]
  run mi_led_find netref key family
  assert_contains "owned=no"
}

@test "an attach-only reference is NEVER authorized for deletion" {
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  mi_net_target "$IDX" >/dev/null
  # WHAT MUST NOT BE THERE, ASKED DIRECTLY. Reading the refusal alone is not enough: the wording
  # "no provenance" also occurs inside the UNLABELLED-object refusal, which this fixture's network
  # would draw anyway — so a mutation that recorded provenance for the operator's network kept the
  # whole suite green. The absence of the record is the property, so the record is what is asked about.
  run mi_prov_find network opnet
  [ "$status" -eq 3 ]
  run mi_prov_authority network opnet
  [ "$status" -ne 0 ]
  assert_contains "has no provenance record"
  # And the thing that SHOULD have happened did: the reference itself is recorded, attach-only.
  run mi_net_ref_get
  [ "$status" -eq 0 ]
  run mi_led_find netref key family
  assert_contains "owned=no"
}

@test "an AMBIGUOUS resolution stops the operation rather than picking one" {
  mi_rt_network_create opnet "" x >/dev/null
  FAKE_DOCKER_NET_DUPLICATE=1 mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_net_ref_resolve opnet
  [ "$status" -ne 0 ]
  assert_contains "more than one"
}

@test "a name that now resolves to a DIFFERENT ID stops and reports — never a silent rebind" {
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  old="$(mi_net_target "$IDX")"
  mi_rt_network_rm opnet >/dev/null
  mi_rt_network_create opnet "" y >/dev/null
  run mi_net_ref_verify
  [ "$status" -ne 0 ]
  assert_contains "resolves to a different"
  assert_contains "confirmed rebind"
  run mi_net_ref_get
  [ "$output" = "$old" ]
}

@test "a MISSING network stops and reports, and still offers the rebind exit" {
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  mi_net_target "$IDX" >/dev/null
  mi_rt_network_rm opnet >/dev/null
  run mi_net_ref_verify
  [ "$status" -ne 0 ]
  assert_contains "rebind"
}

@test "a rebind with NO containers records the new ID directly — there is nothing to migrate" {
  mi_rt_network_create opnet "" x >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  mi_net_target "$IDX" >/dev/null
  mi_rt_network_rm opnet >/dev/null
  new="$(mi_rt_network_create opnet "" y)"
  run mi_net_ref_rebind "$IDX" "$new"
  [ "$status" -eq 0 ]
  run mi_net_ref_get
  [ "$output" = "$new" ]
}

# --- D45: the phased fleet migration ---------------------------------------------------------------

@test "a rebind with siblings connects EVERY container BEFORE any detach" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  a_sibling p1 "$src" >/dev/null
  a_sibling p2 "$src" >/dev/null
  mi_netmig_run "$IDX" "$src" "$tgt" 2
  run mi_rt_inspect container c.nets "mythical-${IDENT}-p1"
  assert_contains "$src"
  assert_contains "$tgt"
  run mi_rt_inspect container c.nets "mythical-${IDENT}-p2"
  assert_contains "$src"
  assert_contains "$tgt"
}

@test "phase 2 attaches the target at a LOWER gateway priority than the source" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  a_sibling p1 "$src" stopped >/dev/null
  mi_netmig_run "$IDX" "$src" "$tgt" 2
  run grep -a -- "--gw-priority" "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
  run grep -a -- "gw-priority -1" "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -eq 0 ]
}

@test "a container carrying our label but ABSENT from provenance stops the migration" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"
  mi_led_del object key "container:${c}"
  run mi_netmig_run "$IDX" "$src" "$tgt" 2
  [ "$status" -ne 0 ]
  assert_contains "no record of it"
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$src"
  run grep -a "$tgt" <<<"$output"
  [ "$status" -ne 0 ]
}

@test "phase 3 compares the ADDRESS, so resolving via the old network does not pass" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"
  mi_netmig_run "$IDX" "$src" "$tgt" 2 >/dev/null
  probe_answers 9.9.9.9
  run mi_netmig_run "$IDX" "$src" "$tgt" 3
  [ "$status" -ne 0 ]
  assert_contains "endpoint address"
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$src"
}

@test "a STOPPED sibling is DEFERRED, not demanded and not started to verify" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src" stopped)"
  # Phase 2 first: a stopped sibling must be ATTACHED to the target before phase 3 will defer its live
  # check — deferring one that never reached the target is exactly the silent-connect split phase 3 now
  # catches (see the critical-2 test below).
  mi_netmig_run "$IDX" "$src" "$tgt" 2 >/dev/null
  run mi_netmig_run "$IDX" "$src" "$tgt" 3
  [ "$status" -eq 0 ]
  run mi_state_observed "$c"
  [ "$output" = stopped ]
  run mi_state_outstanding "$c"
  assert_contains alias
}

@test "an unobtainable probe STOPS the migration at phase 3 and does NOT detach" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"
  mi_netmig_run "$IDX" "$src" "$tgt" 2 >/dev/null
  FAKE_DOCKER_PULL=notfound run mi_netmig_run "$IDX" "$src" "$tgt" 3
  [ "$status" -ne 0 ]
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$src"
}

@test "one SILENTLY FAILED detach is caught at phase 5, BEFORE the commit" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"
  printf 'MYTHICAL_NET=t\n' > "$MYTHICAL_HOME/mythical.conf"
  mi_netmig_run "$IDX" "$src" "$tgt" 2 >/dev/null
  probe_answers "$(addr_on "$c" "$tgt")"
  mi_netmig_run "$IDX" "$src" "$tgt" 3 >/dev/null
  FAKE_DOCKER_DISCONNECT_SILENT=1 mi_netmig_run "$IDX" "$src" "$tgt" 4 >/dev/null || true
  run mi_netmig_run "$IDX" "$src" "$tgt" 5
  [ "$status" -ne 0 ]
  assert_contains "still attached"
  run mi_netmig_phase
  [ "$output" = 4 ]
  run mi_net_ref_get
  [ "$status" -ne 0 ]
}

@test "recovery reads the recorded phase and CONTINUES FORWARD — never unwinds" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"
  printf 'MYTHICAL_NET=t\n' > "$MYTHICAL_HOME/mythical.conf"
  probe_answers "$(addr_will_be "$c" "$tgt")"
  mi_led_put netmig key family "key=family" "phase=2" "source=$src" "target=$tgt" "containers=$c"
  run mi_netmig_resume "$IDX"
  [ "$status" -eq 0 ]
  run mi_net_ref_get
  [ "$output" = "$tgt" ]
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$tgt"
  run grep -a "$src" <<<"$output"
  [ "$status" -ne 0 ]
}

@test "an intent recording only the TARGET cannot complete — the source is required" {
  mi_led_put netmig key family "key=family" "phase=2" "target=abc" "containers=c1"
  run mi_netmig_resume "$IDX"
  [ "$status" -ne 0 ]
  assert_contains "source"
}

@test "a migration phase that is not a number REFUSES rather than reporting success" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"
  mi_led_put netmig key family "key=family" "phase=two" "source=$src" "target=$tgt" "containers=$c"
  run mi_netmig_resume "$IDX"
  [ "$status" -ne 0 ]
  assert_contains "not a number"
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$src"
}

@test "a migration whose source and target are the SAME network is refused outright" {
  src="$(mi_rt_network_create s "" x)"
  c="$(a_sibling p1 "$src")"
  run mi_netmig_run "$IDX" "$src" "$src" 4
  [ "$status" -ne 0 ]
  assert_contains "same network"
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$src"
}

@test "a missing OLD network is recognised as forward-only and named as such" {
  tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$tgt")"
  mi_led_put netmig key family "key=family" "phase=2" \
    "source=0000000000000000000000000000000000000000000000000000000000000099" "target=$tgt" "containers=$c"
  run mi_netmig_resume "$IDX"
  assert_contains "forward-only"
}

@test "committing clears the intent, so the exact-set check resumes immediately" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"
  printf 'MYTHICAL_NET=t\n' > "$MYTHICAL_HOME/mythical.conf"
  probe_answers "$(addr_will_be "$c" "$tgt")"
  mi_led_put netmig key family "key=family" "phase=2" "source=$src" "target=$tgt" "containers=$c"
  mi_netmig_resume "$IDX" >/dev/null
  run mi_led_find netmig key family
  [ "$status" -eq 3 ]
  run mi_bringup_verify_attach "$c" "$tgt" "$(mi_name_alias p1)"
  [ "$status" -eq 0 ]
}

@test "the commit refuses a reference that does not match where the containers actually are" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  other="$(mi_rt_network_create o "" z)"
  c="$(a_sibling p1 "$src")"
  printf 'MYTHICAL_NET=o\n' > "$MYTHICAL_HOME/mythical.conf"
  probe_answers "$(addr_will_be "$c" "$tgt")"
  mi_led_put netmig key family "key=family" "phase=2" "source=$src" "target=$tgt" "containers=$c"
  run mi_netmig_resume "$IDX"
  [ "$status" -ne 0 ]
  assert_contains "$other"
  run mi_led_find netmig key family
  [ "$status" -eq 0 ]
  run mi_net_ref_get
  [ "$status" -ne 0 ]
}

# --- fix wave 1: a fleet must never split across two networks while everything reports healthy -------

# CRITICAL 1 — a config change must not silently record a new network and leave the fleet behind.

@test "adding MYTHICAL_NET to a running installation is REFUSED, not silently split" {
  owned="$(mi_net_target "$IDX")"
  c="$(a_sibling p1 "$owned")"
  mi_rt_network_create opnet "" z >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  run mi_net_target "$IDX"
  [ "$status" -ne 0 ]
  # STATE, not wording: no attach-only reference was recorded, and the fleet is still on the owned
  # network — resolving a target did not flip which network the family joins.
  run mi_net_ref_get
  [ "$status" -eq 3 ]
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$owned"
}

@test "removing MYTHICAL_NET from a running installation is REFUSED, not silently split" {
  mi_rt_network_create opnet "" z >/dev/null
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  op="$(mi_net_target "$IDX")"
  c="$(a_sibling p1 "$op")"
  rm -f "$MYTHICAL_HOME/mythical.conf"
  run mi_net_target "$IDX"
  [ "$status" -ne 0 ]
  # STATE: no installer-owned network was created behind the fleet's back, and the fleet stays on the
  # operator's network — the owned branch did not bypass the reference check.
  run mi_rt_find_by_label network installation "$IDENT"
  [ "$(printf '%s\n' "$output" | grep -ac .)" = 0 ]
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$op"
}

# RESIDUAL (c) — the rebind must be able to migrate the fleet OFF the installer's own network, which is
# what gives critical-1's "adding" case a correct path instead of a record-and-split.

@test "a rebind can migrate the fleet OFF the installer's own network onto an operator's" {
  owned="$(mi_net_target "$IDX")"
  c="$(a_sibling p1 "$owned")"
  op="$(mi_rt_network_create opnet "" z)"
  printf 'MYTHICAL_NET=opnet\n' > "$MYTHICAL_HOME/mythical.conf"
  probe_answers "$(addr_will_be "$c" "$op")"
  run mi_net_ref_rebind "$IDX" "$op"
  [ "$status" -eq 0 ]
  # STATE: the reference now names the operator's network, the fleet is on it, and nothing is left on
  # the owned network.
  run mi_net_ref_get
  [ "$output" = "$op" ]
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$op"
  run grep -a "$owned" <<<"$output"
  [ "$status" -ne 0 ]
}

# CRITICAL 2 — a stopped container that never reached the target must not be deferred-and-passed, or
# phase 4 detaches the source from a container attached to nothing.

@test "phase 3 refuses to defer a STOPPED sibling that never reached the target" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src" stopped)"
  # Phase 3 with NO phase 2 — the state a silently-failed connect leaves: stopped, on the source only.
  run mi_netmig_run "$IDX" "$src" "$tgt" 3
  [ "$status" -ne 0 ]
  # STATE: no deferred alias check toward the target was recorded (the defer was refused, not passed).
  run mi_state_outstanding "$c"
  run grep -a "$tgt" <<<"$output"
  [ "$status" -ne 0 ]
}

# RESIDUAL (b) — a stopped container owing an alias check on the SOURCE cannot be migrated, or the check
# outlives the network it names and can never be satisfied.

@test "phase 3 refuses to migrate a stopped sibling owing an alias check on the source" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src" stopped)"
  mi_state_commit "$c" stopped alias "$src"
  mi_netmig_run "$IDX" "$src" "$tgt" 2 >/dev/null
  run mi_netmig_run "$IDX" "$src" "$tgt" 3
  [ "$status" -ne 0 ]
  # STATE: the stale check is still recorded on the SOURCE (not silently cleared), and nothing detached.
  run mi_state_outstanding "$c"
  assert_contains "$src"
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$src"
}

# CRITICAL 3 — the public single-phase entry point must not detach without proof the connects happened.

@test "a bare phase 4 on a fleet with no recorded migration REFUSES to detach" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"
  run mi_netmig_run "$IDX" "$src" "$tgt" 4
  [ "$status" -ne 0 ]
  # STATE: the source is still attached — nothing was detached on invented proof.
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$src"
}

@test "a FAILED phase 3 does not leave a marker that lets a later phase 4 detach" {
  # "Phase 3 was entered" is not "phase 3 succeeded". The phase=3 marker used to be written on ENTRY,
  # so a phase 3 that then failed its verification left the marker behind — and a subsequent bare
  # phase-4 call, whose gate admits a recorded phase of {3,4}, would detach the source on the strength
  # of a verification that never happened. The marker is now written only after phase 3 succeeds.
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"                       # on the SOURCE only — never connected to the target
  # Phase 3 with no phase 2 first: it must FAIL (the container is not on the target).
  run mi_netmig_run "$IDX" "$src" "$tgt" 3
  [ "$status" -ne 0 ]
  # STATE: the recorded phase is NOT 3 (it is absent, since phase 2 never ran) — so phase 4 is refused.
  run mi_led_find netmig key family
  # either no record at all, or a record whose phase is not 3
  if [ "$status" -eq 0 ]; then
    case "$output" in *"phase=3"*) echo "a failed phase 3 left a phase=3 marker: $output" >&2; return 1 ;; esac
  fi
  # And the operative proof: a phase 4 now REFUSES and the source stays attached.
  run mi_netmig_run "$IDX" "$src" "$tgt" 4
  [ "$status" -ne 0 ]
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$src"
}

@test "a bare phase 6 with no verified migration REFUSES to commit-and-clear" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"
  printf 'MYTHICAL_NET=t\n' > "$MYTHICAL_HOME/mythical.conf"
  # An in-flight migration only at phase 2 (containers still on both, never verified on the target).
  mi_led_put netmig key family "key=family" "phase=2" "source=$src" "target=$tgt" "containers=$c"
  run mi_netmig_run "$IDX" "$src" "$tgt" 6
  [ "$status" -ne 0 ]
  # STATE: the intent is still recorded (not cleared) and no reference was committed over it.
  run mi_led_find netmig key family
  [ "$status" -eq 0 ]
  run mi_net_ref_get
  [ "$status" -ne 0 ]
}

# RESIDUAL (a) — a forward-only migration (source deleted) must CONVERGE, not wedge on a source that is
# gone, using phase 5's exact-{target} topology check.

@test "a forward-only migration (source gone) CONVERGES instead of wedging" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$tgt")"
  printf 'MYTHICAL_NET=t\n' > "$MYTHICAL_HOME/mythical.conf"
  probe_answers "$(addr_on "$c" "$tgt")"
  mi_rt_network_rm s >/dev/null
  mi_led_put netmig key family "key=family" "phase=3" "source=$src" "target=$tgt" "containers=$c"
  run mi_netmig_resume "$IDX"
  [ "$status" -eq 0 ]
  # STATE: the intent is cleared and the reference recorded — the wedge is gone.
  run mi_led_find netmig key family
  [ "$status" -eq 3 ]
  run mi_net_ref_get
  [ "$output" = "$tgt" ]
}

# --- fix wave 2: the fleet is FIXED at intent-open, and phase 3's source inspect keeps 1 apart from 3 --

# CRITICAL — every phase acts on the RECORDED containers= snapshot, never a live re-enumeration. A
# container that appears mid-migration was never connected in phase 2 or verified in phase 3, so phase 4
# must not detach it.

@test "phase 4 detaches only the RECORDED fleet, never a container that appeared mid-migration" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  a="$(a_sibling p1 "$src")"
  # A is in the migration and, as phase 2 left it, attached to BOTH networks.
  mi_rt_network_connect "$tgt" "$a" "$(mi_name_alias p1)" -1 >/dev/null
  # The intent, opened when only A existed, sits at phase 3 (verified) ready for the phase-4 detach.
  mi_led_put netmig key family "key=family" "phase=3" "source=$src" "target=$tgt" "containers=$a"
  # B appears AFTER intent-open: same installation label, on the source only — never connected in
  # phase 2, never verified in phase 3. It is NOT part of this migration.
  b="$(a_sibling p2 "$src")"
  run mi_netmig_run "$IDX" "$src" "$tgt" 4
  [ "$status" -eq 0 ]
  # STATE: A (recorded) is detached from the source — it now holds the target alone.
  run mi_rt_inspect container c.nets "$a"
  run grep -a "$src" <<<"$output"
  [ "$status" -ne 0 ]
  # STATE: B (appeared mid-migration) is UNTOUCHED — still on the source. Re-enumerating the live label
  # set would have swept B into the detach, stranding it on nothing; the recorded snapshot did not.
  run mi_rt_inspect container c.nets "$b"
  assert_contains "$src"
  # RECORD: the migration still names only the fleet it opened against — B was never written into it.
  run mi_led_find netmig key family
  run grep -a "$b" <<<"$output"
  [ "$status" -ne 0 ]
}

# MAJOR fail-open — phase 3 must accept only rc 3 (genuinely gone) as an absent source. rc 1 (the
# daemon could not be asked) is not absence, and folding it in would switch to the forward-only verifier
# and skip the source-egress assertion on the strength of an unanswered question.

@test "phase 3 STOPS when the source network cannot be inspected — could-not-ask is not absent" {
  src="$(mi_rt_network_create s "" x)"; tgt="$(mi_rt_network_create t "" y)"
  c="$(a_sibling p1 "$src")"
  # As phase 2 left it: c on both networks, the intent recorded at phase 3.
  mi_rt_network_connect "$tgt" "$c" "$(mi_name_alias p1)" -1 >/dev/null
  mi_led_put netmig key family "key=family" "phase=3" "source=$src" "target=$tgt" "containers=$c"
  # The daemon cannot answer the source-presence question: every runtime call during the run dies,
  # `version` included, so mi_rt_inspect reports rc 1 (could not ask), NOT rc 3 (genuinely gone). The
  # source inspect is the FIRST runtime call phase 3 makes — the fleet is read from the record — so
  # DOWN_AFTER=0 targets exactly it.
  FAKE_DOCKER_DOWN_AFTER=0 run mi_netmig_run "$IDX" "$src" "$tgt" 3
  [ "$status" -ne 0 ]
  assert_contains "could not inspect the source"
  # STATE: nothing was detached — c is still on the source. A fail-open would have read "source gone",
  # taken the forward-only path, and proceeded on a question the runtime never answered.
  run mi_rt_inspect container c.nets "$c"
  assert_contains "$src"
}
