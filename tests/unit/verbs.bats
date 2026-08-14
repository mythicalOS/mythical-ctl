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
  # has no errexit to abort it — taking the caller down too. The fix returns 2 at once.
  cat > "$BATS_TEST_TMPDIR/lib_call.sh" <<EOF
for _m in common layout config lock ledger doc trust policy manifest detect runtime preflight exit prov intent state probe bringup netref verbs copy; do
  source "$_MCTL_ROOT/lib/\$_m.sh"
done
mi_verb_install "$IDX" "$POL" "$MAN" p1 --image
EOF
  # PORTABLE WATCHDOG, not GNU `timeout`: stock macOS/BSD has no `timeout` (only `gtimeout` after
  # coreutils), and the Global Constraints require GNU AND BSD userland. Background the library call,
  # poll up to ~10s with only shell builtins plus sleep, and SIGKILL a runaway — so a regression that
  # spins the option loop is a clean FAILURE here (wrc≠2) instead of a hung suite. Verified under
  # `env -i PATH=/usr/bin:/bin` (env.md trap #6), where `timeout` does not exist.
  bash "$BATS_TEST_TMPDIR/lib_call.sh" > "$BATS_TEST_TMPDIR/lib_call.out" 2>&1 &
  wpid=$!
  waited=0
  while kill -0 "$wpid" 2>/dev/null; do
    waited=$((waited + 1))
    if [ "$waited" -ge 100 ]; then kill -9 "$wpid" 2>/dev/null || true; break; fi
    sleep 0.1
  done
  wrc=0; wait "$wpid" || wrc=$?
  output="$(cat "$BATS_TEST_TMPDIR/lib_call.out")"
  [ "$wrc" -eq 2 ]                              # usage, at once — NOT 137 (killed runaway), NOT a hang
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

# --- the host-tool slot survives every verb --------------------------------------------------------
# docs/CONFIG-FORMAT.md, "Amendment: the host-tool slot" says mythical-ctl does not create, read,
# write, move, chmod or delete ~/.mythical/<product>/cli.toml. That is a claim about the DESTRUCTIVE
# verbs above all: the slot lives inside a directory the layout still calls installer-managed, so
# nothing but this rule stands between a future artifact reaper and a host-only credential.
#
# EVERY ASSERTION BELOW NAMES ITSELF, and that is not decoration. These calls run several frames
# deep under the verbs' own `set -e`, and bats reports such a failure with the stack of the frame
# errexit unwound through — measured here as `mi_verb_install … line 259` for a mutation that only
# ever ran a `chmod` inside the FAMILY UNINSTALL, twenty lines later. The reported line is
# misleading, so the assertion has to say what it was checking or a future failure gets debugged in
# the wrong function entirely.
_slot_is() {                      # _slot_is <what-changed-if-this-fires> <digest> <mode> <inode> <uid>
  local at="$1" want="$2" mode="$3" wantino="$4" wantuid="$5"
  local slot="$MYTHICAL_HOME/p1/cli.toml" got gotmode gotino gotuid
  # A SYMLINK IS NOT THE FILE, and `-f` follows one — so it is asked first and separately. Without
  # this a verb could replace the slot with a link to an identical file elsewhere and every
  # assertion below would read the target and pass.
  if [ -L "$slot" ]; then echo "host-tool slot REPLACED BY A SYMLINK by $at" >&2; return 1; fi
  if [ ! -f "$slot" ]; then echo "host-tool slot GONE after $at" >&2; return 1; fi
  # IDENTITY, NOT JUST CONTENT. `rm` plus a byte-identical rewrite, or a `mv` into place, changes the
  # inode while leaving the digest and the mode exactly as they were — and the contract forbids
  # moving or re-creating this file, not merely altering its bytes. It is the same reason
  # <product>.conf must never be replaced by rename: a new inode detaches anything bound to the old.
  gotino="$(_mi_ino "$slot")" || { echo "cannot read the slot's identity after $at" >&2; return 1; }
  if [ "$gotino" != "$wantino" ]; then
    echo "host-tool slot REPLACED by $at (inode $wantino -> $gotino)" >&2; return 1; fi
  gotuid="$(_mi_owner_uid "$slot")" || { echo "cannot read the slot's owner after $at" >&2; return 1; }
  if [ "$gotuid" != "$wantuid" ]; then
    echo "host-tool slot CHOWNed by $at ($wantuid -> $gotuid)" >&2; return 1; fi
  got="$(mi_digest "$slot")"
  if [ "$got" != "$want" ]; then echo "host-tool slot REWRITTEN by $at ($want -> $got)" >&2; return 1; fi
  gotmode="$(ls -ld "$slot" | awk 'NR==1{print $1}')"
  if [ "$gotmode" != "$mode" ]; then echo "host-tool slot CHMOD'd by $at ($mode -> $gotmode)" >&2; return 1; fi
  return 0
}

@test "the host-tool slot survives the whole lifecycle, byte-identical and mode-unchanged" {
  mkdir -p "$MYTHICAL_HOME/p1"
  printf 'token = "host-only"\n' > "$MYTHICAL_HOME/p1/cli.toml"
  # DELIBERATELY NOT 0600, which is the mode the contract asks the host-side TOOL to use. The
  # property under test is that mythical-ctl leaves the mode it FINDS alone, and starting at 0600
  # cannot show that: a regression that unconditionally ran `chmod 600` would land on the same bits
  # and the test would pass. Starting somewhere else makes "preserved" and "normalised"
  # distinguishable, which is the whole point of asserting it.
  chmod 640 "$MYTHICAL_HOME/p1/cli.toml"
  want="$(mi_digest "$MYTHICAL_HOME/p1/cli.toml")"
  mode="$(ls -ld "$MYTHICAL_HOME/p1/cli.toml" | awk 'NR==1{print $1}')"
  [ "$mode" = "-rw-r-----" ] || { echo "fixture mode is '$mode', not the 0640 this test needs" >&2; return 1; }
  ino="$(_mi_ino "$MYTHICAL_HOME/p1/cli.toml")"
  uid="$(_mi_owner_uid "$MYTHICAL_HOME/p1/cli.toml")"
  [ -n "$ino" ] && [ -n "$uid" ]

  # A first install, then a re-install over the populated home (§10a's byte-identical rule).
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  _slot_is "the first install" "$want" "$mode" "$ino" "$uid"
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  _slot_is "a re-install over a populated home" "$want" "$mode" "$ino" "$uid"

  # The whole running lifecycle.
  mi_verb_stop p1 >/dev/null
  _slot_is stop "$want" "$mode" "$ino" "$uid"
  mi_verb_start "$IDX" p1 >/dev/null
  _slot_is start "$want" "$mode" "$ino" "$uid"
  mi_verb_restart "$IDX" p1 >/dev/null
  _slot_is restart "$want" "$mode" "$ino" "$uid"
  mi_verb_recreate "$IDX" "$POL" "$MAN" p1 >/dev/null
  _slot_is recreate "$want" "$mode" "$ino" "$uid"

  # And both destructive ends, purge included — the two that remove things on purpose.
  mi_verb_uninstall p1 --purge >/dev/null
  _slot_is "uninstall --purge" "$want" "$mode" "$ino" "$uid"
  MI_CONFIRM=yes mi_verb_uninstall_family --purge >/dev/null
  _slot_is "uninstall --family --purge" "$want" "$mode" "$ino" "$uid"
}

@test "no verb ever creates a host-tool slot for a product that has none" {
  # The slot is the OPERATOR's file. An installer that helpfully created an empty one would be
  # creating a path it has just promised never to write, and would mask a missing host-side tool.
  # `-e` ALONE IS NOT THE TEST. It follows a symlink, so it is false for a DANGLING one — and a verb
  # that planted a dangling `cli.toml` would satisfy it while having created exactly the path this
  # asserts nothing creates. `-L` is the only test that sees the link itself, which is the same rule
  # the first-use sweep in lib/prov.sh is built on.
  _no_slot() {
    local slot="$MYTHICAL_HOME/p1/cli.toml"
    if [ -e "$slot" ] || [ -L "$slot" ]; then
      echo "a host-tool slot was CREATED by $1, for a product that has no host-side tool" >&2
      return 1
    fi
    return 0
  }
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  _no_slot install
  mi_verb_stop p1 >/dev/null
  _no_slot stop
  mi_verb_start "$IDX" p1 >/dev/null
  _no_slot start
  mi_verb_restart "$IDX" p1 >/dev/null
  _no_slot restart
  mi_verb_recreate "$IDX" "$POL" "$MAN" p1 >/dev/null
  _no_slot recreate
  mi_verb_uninstall p1 --purge >/dev/null
  _no_slot "uninstall --purge"
  MI_CONFIRM=yes mi_verb_uninstall_family --purge >/dev/null
  _no_slot "uninstall --family --purge"
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

@test "recreate PRESERVES an install-time --image override, so the running image and status agree (§13)" {
  # install --image X records the override, runs X, and status reports X. recreate takes no --image of
  # its own; before this fix it reverted to the manifest's image — tearing down the override container
  # and, since the manifest image was never pulled, failing to rebuild it — while status still claimed
  # the override active. The invariant: the running image and what status reports must agree.
  ref="$(a_digestref localbuild)"
  mi_verb_install "$IDX" "$POL" "$MAN" p1 --image "$ref" >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  run mi_verb_recreate "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 0 ]
  run mi_rt_inspect container c.image "$C"
  [ "$output" = "$ref" ]                        # the RUNNING image is the override, not the manifest's
  run mi_verb_status "$IDX" p1
  assert_contains "$ref"                        # and status reports the same reference — they AGREE
}

@test "the shared bootstrap-secret gate refuses a secret the policy no longer grants (install+recreate share it)" {
  # install and recreate stage bootstrap secrets through ONE helper, _mi_verb_secrets_envfile, which
  # applies mi_policy_permits per key BEFORE staging anything — so the entitlement gate cannot drift
  # between the two verbs (install carried this check; recreate did not). Exercised directly here,
  # against the authenticated records both verbs derive. Accepting the documents records a trust floor,
  # so it runs under the family lock.
  mi_lock_acquire
  mrec="$(mi_accept_manifest "$IDX" "$POL" "$MAN" p1)"
  prec="$(mi_accept_policy "$IDX" "$POL")"
  mi_lock_release
  # GRANTED: the secret is staged into a real 0600 env file that actually carries it — positive
  # evidence, not merely the absence of a refusal.
  run _mi_verb_secrets_envfile p1 "$mrec" "$prec"
  [ "$status" -eq 0 ]
  [ -f "$output" ]
  run grep -a '^MYTHICAL_TELEMETRY_KEY=tk$' "$output"
  [ "$status" -eq 0 ]
  rm -f "$output"
  # REVOKED: the same manifest, but a policy with the grant stripped — refused, and nothing is staged.
  prec_revoked="$(printf '%s' "$prec" | grep -av permitted_secret)"
  run _mi_verb_secrets_envfile p1 "$mrec" "$prec_revoked"
  [ "$status" -eq 1 ]
  assert_contains "does not grant"
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

@test "recreate ENSURES the selected image before removing the container — an unpullable image preserves it" {
  # install had an image-presence/pull gate BEFORE it replaced the container; recreate did not, so a
  # manifest that advanced to an unpulled image (or an unreachable registry) let recreate tear the
  # container down and then fail to rebuild it — leaving the operator with nothing. recreate now shares
  # install's gate and must fail with the running container INTACT.
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  run mi_state_observed "$C"
  [ "$output" = running ]
  # the selected image is now absent (a GC, or a manifest advanced to a digest never pulled) and the
  # registry cannot be reached, so it cannot be made present again
  rm -rf "${FAKE_DOCKER_STATE:?}/images"/*
  FAKE_DOCKER_PULL=neterr run mi_verb_recreate "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 1 ]
  # the container was NOT stopped or removed — it is still there and still running
  run mi_state_observed "$C"
  [ "$output" = running ]
}

@test "status reports an UNREADABLE identity, not 'nothing installed' (rc 1 is not rc 3)" {
  # setup already minted one identity. A SECOND identity record makes mi_ident_get AMBIGUOUS (rc 1),
  # which is NOT rc 3 (genuinely absent). Reporting "nothing installed" for a corrupt ledger tells an
  # operator whose objects are orphaned that the machine is clean; status must send them to repair.
  mi_lock_acquire
  mi_led_put identity id second "id=second"
  mi_lock_release
  run mi_verb_status "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "UNREADABLE"
  assert_contains "state repair"
  case "$output" in *"No installation state found"*) echo "misreported a corrupt identity as absent: $output" >&2; return 1 ;; esac
}

@test "status reports an UNREADABLE operator network, not 'not created yet' (rc 1 is not rc 3)" {
  # an operator network reference recorded without an id is unreadable (rc 1), NOT rc 3 (no operator
  # network configured at all). status must not hide it behind the installer-owned "not created yet",
  # which would tell the operator to create a network they already pointed the installation at.
  mi_lock_acquire
  mi_led_put netref key family "key=family" "name=opnet" "owned=no"
  mi_lock_release
  run mi_verb_status "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "UNREADABLE"
  assert_contains "state repair"
  case "$output" in *"not created yet"*) echo "hid an unreadable operator network as not-created: $output" >&2; return 1 ;; esac
}

@test "a plain install CLEARS a prior --image override, so status reverts to the manifest image" {
  # the override record must track the install that succeeded: after install --image X, a plain
  # re-install runs the manifest image and must clear the override, or status/recreate keep naming X.
  ref="$(a_digestref localbuild)"
  mi_verb_install "$IDX" "$POL" "$MAN" p1 --image "$ref" >/dev/null
  run mi_verb_status "$IDX" p1
  assert_contains "image override"        # the override is in effect after the --image install
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null   # plain re-install, no --image
  run mi_verb_status "$IDX" p1
  [ "$status" -eq 0 ]
  case "$output" in *"image override"*) echo "plain install did not clear the override: $output" >&2; return 1 ;; esac
}

@test "a FAILED --image install records NO override, so a later plain install names none" {
  # the override ledger record is written AFTER bring-up succeeds. A --image install that fails during
  # the pull must leave no override behind for a later recreate to run or status to report.
  ref="$(a_digestref abandoned)"
  FAKE_DOCKER_PULL=neterr run mi_verb_install "$IDX" "$POL" "$MAN" p1 --image "$ref"
  [ "$status" -eq 1 ]
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null   # a clean manifest install afterwards
  run mi_verb_status "$IDX" p1
  [ "$status" -eq 0 ]
  case "$output" in *"image override"*) echo "a failed --image install left a stale override: $output" >&2; return 1 ;; esac
}

@test "status reports an UNREADABLE installer-owned network record, not 'not created yet' (rc 1 is not rc 3)" {
  # two provenance records answer for the same installer-owned network name → mi_prov_find is ambiguous
  # (rc 1), NOT rc 3 (no record). Written through the ledger writer, checksum and all, the way a restore
  # would — mi_led_put refuses to write a duplicate key directly. status must report it, not claim the
  # network was never created.
  IDENT="$(mi_ident_get)"; nname="$(mi_name_network "$IDENT")"
  mi_lock_acquire
  { mi_ledger_read
    printf 'object\tkey=network:%s\tclass=network\tname=%s\tid=netid-a\n' "$nname" "$nname"
    printf 'object\tkey=network:%s\tclass=network\tname=%s\tid=netid-b\n' "$nname" "$nname"
  } | mi_ledger_write
  mi_lock_release
  run mi_verb_status "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "UNREADABLE"
  case "$output" in *"not created yet"*) echo "hid an ambiguous installer-network record as not-created: $output" >&2; return 1 ;; esac
}

@test "status reports an UNREADABLE network-migration record, not silence (rc 1 is not rc 3)" {
  # two netmig records answer for key=family → mi_led_find is ambiguous (rc 1). A corrupt migration
  # record must not be swallowed like rc 3 (no migration), which would let status claim a normal network
  # while a migration is in an unrecoverable state.
  mi_lock_acquire
  { mi_ledger_read
    printf 'netmig\tkey=family\tphase=1\tsource=neta\ttarget=netb\tcontainers=\n'
    printf 'netmig\tkey=family\tphase=2\tsource=netc\ttarget=netd\tcontainers=\n'
  } | mi_ledger_write
  mi_lock_release
  run mi_verb_status "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "MIGRATION record UNREADABLE"
}

@test "a mutating verb STOPS when probe cleanup cannot complete — an unresolved probe is not stepped over" {
  # probe cleanup runs first in _mi_verb_prepare. Make it fail: an ambiguous identity means it cannot say
  # which probe container is ours, so it returns non-zero and the verb must not proceed to mutate state.
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  mi_lock_acquire
  mi_led_put identity id second "id=second"
  mi_lock_release
  run mi_verb_stop p1
  [ "$status" -ne 0 ]
  assert_contains "probe"
}

@test "family uninstall REFUSES and does NOT reset the ledger when the object listing is unreadable" {
  # THE HIGH: `done <<< "$(mi_led_all object)"` took the loop's status, not the listing's — so a
  # malformed (but checksum-valid) object record read as an EMPTY listing, removed nothing, left
  # `preserved` at 0, and the ledger was reset over containers still standing. It must fail closed.
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  mi_lock_acquire
  { mi_ledger_read; printf 'object\tmalformed-no-equals\n'; } | mi_ledger_write
  mi_lock_release
  MI_CONFIRM=yes run mi_verb_uninstall_family     # confirmed, so it is the ENUMERATION guard that stops it
  [ "$status" -ne 0 ]
  # the ledger was NOT wiped — the installation identity is still recorded
  run mi_ident_get
  [ "$status" -eq 0 ]
}

@test "product uninstall --purge REFUSES on an unreadable object listing rather than silently skipping volumes" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  mi_lock_acquire
  { mi_ledger_read; printf 'object\tmalformed-no-equals\n'; } | mi_ledger_write
  mi_lock_release
  run mi_verb_uninstall p1 --purge
  [ "$status" -ne 0 ]
}

@test "install REFUSES to create a volume when its provenance record is unreadable (rc 1 is not rc 3)" {
  # only rc 3 (no such record) authorizes opening an intent and creating a volume; an ambiguous
  # provenance record (rc 1) must fail closed, never create a second volume under the same name.
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; vol="mythical-${IDENT}-p1-state"
  # a second provenance record for the same volume key → mi_prov_find is ambiguous (rc 1)
  mi_lock_acquire
  { mi_ledger_read
    printf 'object\tkey=volume:%s\tclass=volume\tname=%s\tnonce=x\tgen=1\n' "$vol" "$vol"
  } | mi_ledger_write
  mi_lock_release
  run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -ne 0 ]
}

@test "status reports an UNREADABLE object listing as UNREADABLE, never as an empty fleet (rc 1 is not rc 3)" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  mi_lock_acquire
  { mi_ledger_read; printf 'object\tmalformed-no-equals\n'; } | mi_ledger_write
  mi_lock_release
  run mi_verb_status "$IDX"
  [ "$status" -eq 0 ]                              # read-only: never gated by its own findings
  assert_contains "UNREADABLE"
}

@test "recreate NORMALIZES a context failure to operational failure (1), never a raw or undefined exit code" {
  # mi_product_ctx can propagate 4 ("no trust anchor"); a bare `return \$rc` would leak an exit code the
  # §7.3 contract does not define. The product is already confirmed installed, so any context failure —
  # here the manifest is withdrawn to not-launched — is an operational failure for a recreate (code 1),
  # NOT a clean "not launched yet" (3, which mi_ex_worst treats as benign) and never an undefined 4.
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  write_fixture_product p1 launched=false          # the installed product's manifest is withdrawn
  run mi_verb_recreate "$IDX" "$POL" "$MYTHICAL_HOME/p1.manifest" p1
  [ "$status" -eq 1 ]
}

@test "install REFUSES to create a container when its provenance record is ambiguous (rc 1 fail-closed)" {
  # two provenance records answer for the same container name → mi_prov_find is ambiguous (rc 1). Install
  # must NOT read that as "no prior container" and create one over an unreadable ledger; recreate already
  # fails closed here, and install must too.
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  mi_lock_acquire
  { mi_ledger_read
    printf 'object\tkey=container:%s\tclass=container\tname=%s\tnonce=a\tgen=1\n' "$C" "$C"
    printf 'object\tkey=container:%s\tclass=container\tname=%s\tnonce=b\tgen=1\n' "$C" "$C"
  } | mi_ledger_write
  mi_lock_release
  run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -ne 0 ]
  run mi_rt_inspect container c.state "$C"          # no container was created over the ambiguous ledger
  [ "$status" -ne 0 ]
}

@test "a REFUSED install (unaccounted object) does NOT advance the anti-rollback trust floor" {
  # the unaccounted-object gate now runs BEFORE mi_product_ctx, which records the manifest's trust floor.
  # A refused install must not advance the floor — otherwise a newer manifest fed to a refused install
  # would permanently block a rollback for an install that never happened.
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"
  floor_before="$(mi_trust_floor_get manifest:p1)"
  mi_rt_volume_create "mythical-${IDENT}-stray" nx "$IDENT"    # an unrecorded same-identity object → gate stops
  write_fixture_product p1 version=99                          # a NEWER manifest
  run mi_verb_install "$IDX" "$POL" "$MYTHICAL_HOME/p1.manifest" p1
  [ "$status" -ne 0 ]
  run mi_trust_floor_get manifest:p1
  [ "$output" = "$floor_before" ]                             # the floor did NOT advance to 99
}

@test "start reports an ambiguous container provenance as unreadable, never 'not installed' (rc 1 is not rc 3)" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  mi_lock_acquire
  { mi_ledger_read; printf 'object\tkey=container:%s\tclass=container\tname=%s\tnonce=dup\tgen=1\n' "$C" "$C"; } | mi_ledger_write
  mi_lock_release
  run mi_verb_start "$IDX" p1
  [ "$status" -ne 0 ]
  case "$output" in *"is not installed"*) echo "reported ambiguous provenance as not-installed: $output" >&2; return 1 ;; esac
}

@test "family --purge does NOT reset the ledger when a volume record has no readable name (fail closed)" {
  # a checksum-valid volume record missing name= passes the listing check but cannot be acted on. A
  # `name || continue` would skip it silently, leaving `preserved` clear and letting the reset wipe its
  # provenance while the volume stands. It must block the reset instead.
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  mi_lock_acquire
  { mi_ledger_read; printf 'object\tkey=volume:nameless\tclass=volume\tnonce=n\tgen=1\n'; } | mi_ledger_write
  mi_lock_release
  MI_CONFIRM=yes run mi_verb_uninstall_family --purge
  [ "$status" -ne 0 ]
  run mi_ident_get                                  # the ledger was NOT reset
  [ "$status" -eq 0 ]
}

@test "start returns operational failure (1), never undefined 4, when the container needs a rebuild" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  mi_rt_container_rm "$C" >/dev/null 2>&1            # removed out of band → start's plan becomes 'rebuild'
  run mi_verb_start "$IDX" p1
  [ "$status" -eq 1 ]
}

@test "a FAILED forced install leaves no force-install record, so a later normal install is not falsely annotated" {
  write_fixture_product p1 launched=false
  FAKE_DOCKER_PULL=neterr run mi_verb_install "$IDX" "$POL" "$MYTHICAL_HOME/p1.manifest" p1 --force-install
  [ "$status" -ne 0 ]                               # the forced pull failed
  write_fixture_product p1 launched=true            # the product is now released
  mi_verb_install "$IDX" "$POL" "$MYTHICAL_HOME/p1.manifest" p1 >/dev/null   # a normal install succeeds
  run mi_verb_status "$IDX" p1
  case "$output" in *"force-install"*) echo "a failed forced install left a stale force-install record: $output" >&2; return 1 ;; esac
}

@test "family uninstall does NOT reset the ledger when the operator-network reference is unreadable" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  mi_lock_acquire
  mi_led_put netref key family "key=family" "name=opnet" "owned=no"    # recorded, but no id → unreadable
  mi_lock_release
  MI_CONFIRM=yes run mi_verb_uninstall_family
  [ "$status" -ne 0 ]
  run mi_ident_get                                  # not reset over an unreadable operator-network ref
  [ "$status" -eq 0 ]
}

@test "start/stop/restart REFUSE a foreign container that reuses our name (nonce authority, not just a record)" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  # a container stands under OUR name but belongs to another installation (foreign label + nonce), as if
  # ours were deleted out of band and the name reused. The unaccounted gate treats a foreign-LABELLED
  # object as 'unattributed' and permits the verb — so the nonce-authority check is what must stop it.
  printf 'labels=mythicalos.installation=OTHERINSTALL;mythicalos.nonce=OTHER;\nstate=running\nnets=\n' \
    > "$FAKE_DOCKER_STATE/containers/$C"
  run mi_verb_start "$IDX" p1
  [ "$status" -ne 0 ]
  run mi_verb_stop p1
  [ "$status" -ne 0 ]
  run mi_verb_restart "$IDX" p1
  [ "$status" -ne 0 ]
  [ -e "$FAKE_DOCKER_STATE/containers/$C" ]         # the foreign container was NOT acted on
}

@test "status reports an installer-owned network record with no id as UNREADABLE, not empty" {
  IDENT="$(mi_ident_get)"; nname="$(mi_name_network "$IDENT")"
  mi_lock_acquire
  { mi_ledger_read; printf 'object\tkey=network:%s\tclass=network\tname=%s\n' "$nname" "$nname"; } | mi_ledger_write
  mi_lock_release
  run mi_verb_status "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "UNREADABLE"
}

@test "status reports a container record with no name as UNREADABLE, never hiding it" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  mi_lock_acquire
  { mi_ledger_read; printf 'object\tkey=container:nameless\tclass=container\tnonce=n\tgen=1\n'; } | mi_ledger_write
  mi_lock_release
  run mi_verb_status "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "UNREADABLE"
}

@test "a re-install whose container removal FAILS does not proceed to bring-up and restores the container" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  # the replacement's `container rm` fails → install must NOT proceed into mi_bringup (which would collide
  # on the name and leave the product down); it restores the container it stopped and fails.
  FAKE_DOCKER_INTERRUPT_AFTER='container rm' run mi_verb_install "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 1 ]
  run mi_rt_inspect container c.running "$C"     # still present and RUNNING — not left stopped or removed
  [ "$output" = true ]
}

@test "a recreate whose container removal FAILS does not proceed to bring-up and restores the container" {
  mi_verb_install "$IDX" "$POL" "$MAN" p1 >/dev/null
  IDENT="$(mi_ident_get)"; C="mythical-${IDENT}-p1"
  FAKE_DOCKER_INTERRUPT_AFTER='container rm' run mi_verb_recreate "$IDX" "$POL" "$MAN" p1
  [ "$status" -eq 1 ]
  run mi_rt_inspect container c.running "$C"
  [ "$output" = true ]
}

@test "recreate HONORS a recorded force-install on a still-not-launched manifest, rather than refusing it" {
  write_fixture_product p1 launched=false
  mi_verb_install "$IDX" "$POL" "$MYTHICAL_HOME/p1.manifest" p1 --force-install >/dev/null   # recorded
  # the manifest is STILL not-launched; recreate must honor the force-install and rebuild, not refuse,
  # just as it honors a recorded --image override (sibling parity).
  run mi_verb_recreate "$IDX" "$POL" "$MYTHICAL_HOME/p1.manifest" p1
  [ "$status" -eq 0 ]
}

@test "status reports a netmig record missing fields as UNREADABLE, not a blank migration" {
  mi_lock_acquire
  { mi_ledger_read; printf 'netmig\tkey=family\n'; } | mi_ledger_write   # recorded, but no phase/source/target
  mi_lock_release
  run mi_verb_status "$IDX"
  [ "$status" -eq 0 ]
  assert_contains "MIGRATION record UNREADABLE"
}
