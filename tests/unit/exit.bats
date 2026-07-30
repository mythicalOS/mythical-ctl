#!/usr/bin/env bats
load '../lib/test_helper'

setup() { setup_test_env; load_mctl; }
teardown() { teardown_test_env; }

@test "the four codes are exactly §7.3's" {
  [ "$MI_EX_OK" -eq 0 ]
  [ "$MI_EX_FAIL" -eq 1 ]
  [ "$MI_EX_USAGE" -eq 2 ]
  [ "$MI_EX_NOTLAUNCHED" -eq 3 ]
}

@test "batch precedence is worst-wins: all success is 0" {
  run mi_ex_worst 0 0 0
  [ "$output" = 0 ]
}

@test "success plus not-launched is 3" {
  run mi_ex_worst 0 3 0
  [ "$output" = 3 ]
}

@test "any operational failure wins over not-launched" {
  run mi_ex_worst 0 3 1
  [ "$output" = 1 ]
  run mi_ex_worst 1 3
  [ "$output" = 1 ]
}

@test "a usage error is never aggregated — it is returned before anything is attempted" {
  run mi_ex_worst 0 2
  [ "$status" -ne 0 ]
  assert_contains "usage errors are not batch outcomes"
}

@test "an empty batch is a usage error, not a success" {
  run mi_ex_worst
  [ "$status" -ne 0 ]
}

@test "an unknown code is refused rather than mapped to failure" {
  run mi_ex_worst 0 7
  [ "$status" -ne 0 ]
  assert_contains "not an exit code this contract defines"
}

@test "every code has a human name, for reports" {
  run mi_ex_name 3
  assert_contains "not launched"
}
