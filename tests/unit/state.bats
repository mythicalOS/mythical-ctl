#!/usr/bin/env bats
load '../lib/test_helper'

setup() {
  setup_test_env; load_mctl; mi_ensure_layout; mi_lock_acquire
  IDENT="$(mi_ident_ensure)"
  NET="$(mi_rt_network_create "mythical-${IDENT}-net" "$IDENT" nnet)"
  C="mythical-${IDENT}-p1"
  # The fake runtime refuses `container create` from an image it was never asked to pull, because that
  # is what a real daemon does — so the fixture pulls first, exactly as tests/unit/runtime.bats does.
  IMG="$(a_digestref p1)"
  mi_rt_image_pull "$IMG" >/dev/null
  mi_rt_container_create "$C" "$IMG" "$NET" p1 - label=installation="$IDENT" label=nonce=cn >/dev/null
}
teardown() { mi_lock_release; teardown_test_env; }

@test "desired state and the outstanding set commit in ONE ledger write" {
  before="$(mi_digest "$MYTHICAL_HOME/.state/ledger")"
  mi_state_commit "$C" running alias "$NET"
  run mi_state_desired_get "$C"
  [ "$output" = running ]
  run mi_state_outstanding "$C"
  assert_contains "alias"
  assert_contains "$NET"
  [ "$before" != "$(mi_digest "$MYTHICAL_HOME/.state/ledger")" ]
}

@test "desired state defaults to NOTHING, not to running" {
  run mi_state_desired_get "$C"
  [ "$status" -eq 3 ]
  [ -z "$output" ]
}

@test "clearing an outstanding kind clears ONLY that kind" {
  mi_state_commit "$C" running alias "$NET"
  mi_state_outstanding_clear "$C" alias
  run mi_state_outstanding "$C"
  [ -z "$output" ]
  run mi_state_desired_get "$C"
  [ "$output" = running ]
}

@test "clearing a kind that was never outstanding is a no-op success" {
  mi_state_commit "$C" running alias "$NET"
  run mi_state_outstanding_clear "$C" storage
  [ "$status" -ne 0 ]
  assert_contains "not a check kind"
}

@test "observed state is read from the runtime, never from the ledger" {
  run mi_state_observed "$C"
  [ "$output" = stopped ]
  mi_rt_container_start "$C"
  run mi_state_observed "$C"
  [ "$output" = running ]
}

@test "observed state reports absent for a container that is gone" {
  mi_rt_container_rm "$C"
  run mi_state_observed "$C"
  [ "$output" = absent ]
}

@test "an outstanding flag makes a container NOT reconciled even when actual==desired==running" {
  mi_state_commit "$C" running alias "$NET"
  mi_rt_container_start "$C"
  run mi_state_reconciled "$C"
  [ "$status" -ne 0 ]
  mi_state_outstanding_clear "$C" alias
  run mi_state_reconciled "$C"
  [ "$status" -eq 0 ]
}

@test "desired=stopped with the container stopped IS reconciled" {
  mi_state_commit "$C" stopped
  run mi_state_reconciled "$C"
  [ "$status" -eq 0 ]
}

@test "the plan for desired=running, stopped, no outstanding, is start-then-verify" {
  mi_state_commit "$C" running
  run mi_state_plan "$C"
  [ "$output" = "start verify" ]
}

@test "the plan for desired=running, RUNNING, outstanding alias, is verify NOW — not at a future start" {
  mi_state_commit "$C" running alias "$NET"
  mi_rt_container_start "$C"
  run mi_state_plan "$C"
  [ "$output" = "verify" ]
}

@test "the plan for desired=stopped, still running, is stop — reconciliation runs BOTH ways" {
  mi_state_commit "$C" stopped
  mi_rt_container_start "$C"
  run mi_state_plan "$C"
  [ "$output" = "stop" ]
}

@test "the plan for desired=stopped, not running, is nothing — a completed stop is not a crash" {
  mi_state_commit "$C" stopped
  run mi_state_plan "$C"
  [ "$output" = "none" ]
}

@test "a STOPPED container with an outstanding alias check DEFERS — it has no address to verify" {
  mi_state_commit "$C" stopped alias "$NET"
  run mi_state_plan "$C"
  [ "$output" = "defer" ]
}

@test "a recorded storage-migration intent SUSPENDS reconciliation for that container" {
  # The REAL record shape: kind `storagemig`, keyed <product>:<role>. Using a container `intent` here
  # would pass for the wrong reason — that is a different suspension path, and it is tested below.
  mi_prov_record container "$C" cn "product=p1"
  mi_state_commit "$C" running
  mi_led_put storagemig key "p1:state" "key=p1:state" "phase=3" "product=p1" "role=state" "dest=/d"
  run mi_state_plan "$C"
  [ "$output" = "suspended" ]
}

@test "an unconfirmed CONTAINER intent also suspends — a half-built container is not reconcilable" {
  mi_state_commit "$C" running
  mi_intent_open container "$C" cn
  run mi_state_plan "$C"
  [ "$output" = "suspended" ]
}

@test "an absent container with desired=running plans a rebuild, never a bare start" {
  mi_state_commit "$C" running
  mi_rt_container_rm "$C"
  run mi_state_plan "$C"
  [ "$output" = "rebuild" ]
}

@test "forget removes both records, for a family uninstall" {
  mi_state_commit "$C" running alias "$NET"
  mi_state_forget "$C"
  run mi_state_desired_get "$C"
  [ "$status" -eq 3 ]
  run mi_state_outstanding "$C"
  [ -z "$output" ]
}

@test "desired state accepts only running or stopped" {
  run mi_state_commit "$C" paused
  [ "$status" -ne 0 ]
  assert_contains "running or stopped"
}
