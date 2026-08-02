#!/usr/bin/env bats
# §10a — the lifecycle verbs through the ACTUAL CLI: verb dispatch, the batch driver's worst-wins
# aggregate, the §7.3 exit-code contract, and the loopback-publish + network-mode invariants observed
# on the real runtime object.
#
# HELPER_RESOLVE_ADDR is left unset: the fixture probe resolves each container against the runtime's
# real DNS view, so a fresh install's live verification passes for every product without a per-product
# knob — which a single environment variable could not provide for a multi-product batch anyway.
load '../lib/test_helper'
load '../harness/snapshot.sh'

setup() { setup_test_env; install_helper_img; load_mctl; mi_ensure_layout
          write_fixture_product p1; write_fixture_product p2; }
teardown() { teardown_test_env; }

@test "CLI: an unknown verb exits 2" {
  run_mctl frobnicate
  [ "$status" -eq 2 ]
}

@test "CLI: install with no product exits 2 and attempts nothing" {
  snap_runtime "$BATS_TEST_TMPDIR/r0"
  run_mctl install
  [ "$status" -eq 2 ]
  snap_runtime "$BATS_TEST_TMPDIR/r1"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/r0" "$BATS_TEST_TMPDIR/r1"
  [ "$status" -eq 0 ]
}

@test "batch: all products succeed → 0" {
  run_mctl install p1 p2 --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                         --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 0 ]
}

@test "batch: one succeeds, one not-launched → 3" {
  write_fixture_product p2 launched=false
  run_mctl install p1 p2 --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                         --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 3 ]
  assert_contains "p1"
  assert_contains "has not launched yet"
}

@test "batch: any failure → 1, even when another product installed fine" {
  run_mctl install p1 nosuch --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                             --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 1 ]
}

@test "batch: FAILING ONE PRODUCT MUST NOT ABORT THE OTHERS — the later product still installs" {
  run_mctl install nosuch p1 --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                             --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 1 ]
  load_mctl
  run mi_member_has p1
  [ "$status" -eq 0 ]
}

@test "batch reports per product" {
  write_fixture_product p2 launched=false
  run_mctl install p1 p2 --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                         --manifest-dir "$MYTHICAL_HOME"
  assert_contains "p1: completed"
  assert_contains "p2: not launched yet"
}

@test "a first-ever not-launched install mints NO identity or product state (§10a: no product state)" {
  # On a brand-new machine (this suite's setup mints no identity), a not-launched install must create
  # NO installer state: no identity, no membership, no product. Learning from an authentic manifest
  # that a product is unpublished cannot be the act that turns a fresh machine into an installation.
  # The trust floor IS still recorded (§7.3-exempt, pinned in verbs.bats), so the ledger file exists
  # for that reason — what must be absent is the IDENTITY and any product state.
  write_fixture_product p1 launched=false
  run_mctl install p1 --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                      --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 3 ]
  assert_contains "has not launched yet"
  load_mctl
  run mi_ident_get
  [ "$status" -eq 3 ]        # NO installation identity was minted
  run mi_member_has p1
  [ "$status" -ne 0 ]        # NO membership
}

@test "CLI: a value-taking option with no value is a usage error (2), not an operational failure (1)" {
  run_mctl install p1 --index
  [ "$status" -eq 2 ]
  run_mctl install p1 --policy
  [ "$status" -eq 2 ]
  run_mctl install p1 --manifest-dir
  [ "$status" -eq 2 ]
  run_mctl install p1 --image
  [ "$status" -eq 2 ]
}

@test "an interrupted install converges on a re-run, with no half-state" {
  # Interrupt AFTER the volume intent is written but before the container exists.
  FAKE_DOCKER_INTERRUPT_AFTER='container create' run_mctl install p1 \
      --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -ne 0 ]
  run_mctl install p1 --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                      --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 0 ]
}

@test "every published port binds 127.0.0.1 on the ACTUAL runtime object" {
  run_mctl install p1 --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                      --manifest-dir "$MYTHICAL_HOME"
  load_mctl; IDENT="$(mi_ident_get)"
  run mi_rt_inspect container c.ports "mythical-${IDENT}-p1"
  assert_contains "127.0.0.1"
  run grep -a '0\.0\.0\.0' <<<"$output"
  [ "$status" -ne 0 ]
}

@test "network mode host in mythical.conf is rejected" {
  printf 'MYTHICAL_NET=host\n' > "$MYTHICAL_HOME/mythical.conf"
  run_mctl install p1 --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                      --manifest-dir "$MYTHICAL_HOME"
  [ "$status" -eq 1 ]
}

@test "two concurrent installs are serialized under the family lock, with no lost state" {
  ( run_mctl install p1 --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                        --manifest-dir "$MYTHICAL_HOME" >/dev/null 2>&1 ) &
  ( run_mctl install p2 --index "$MYTHICAL_HOME/index" --policy "$MYTHICAL_HOME/policy" \
                        --manifest-dir "$MYTHICAL_HOME" >/dev/null 2>&1 ) &
  wait
  load_mctl
  # The family lock serializes the two: the loser refuses cleanly (before any state write) rather than
  # corrupting the winner's ledger, and whichever product IS a member has its named volume recorded and
  # present — a lost or clobbered install would leave a member with no volume. The port is not
  # persisted, so there is no shared config key for the two to race over; the shared state that IS
  # written concurrently is the ledger, and this asserts it survived intact.
  IDENT="$(mi_ident_get)"
  local p any=0
  for p in p1 p2; do
    if mi_member_has "$p"; then
      any=1
      run mi_rt_inspect volume v.nonce "mythical-${IDENT}-${p}-state"
      [ "$status" -eq 0 ]
    fi
  done
  [ "$any" -eq 1 ]
}
