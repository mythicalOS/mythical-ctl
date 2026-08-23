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

# The `$status` assertions in the three tests below are not decoration. Asserting $output alone lets
# a mutation that prints the correct code and then returns non-zero pass every one of them — and a
# caller reading this contract branches on BOTH: the status says "the aggregation itself succeeded",
# the output carries the aggregate. A test that checks one of the two pins half the interface.
@test "batch precedence is worst-wins: all success is 0" {
  run mi_ex_worst 0 0 0
  [ "$status" -eq 0 ]
  [ "$output" = 0 ]
}

@test "success plus not-launched is 3" {
  run mi_ex_worst 0 3 0
  [ "$status" -eq 0 ]
  [ "$output" = 3 ]
}

@test "any operational failure wins over not-launched" {
  run mi_ex_worst 0 3 1
  [ "$status" -eq 0 ]
  [ "$output" = 1 ]
  run mi_ex_worst 1 3
  [ "$status" -eq 0 ]
  [ "$output" = 1 ]
}

# BOTH ORDERINGS, in this test and the next. The refusal used to be reachable only when the bad code
# came FIRST: the loop returned on the first `1` it saw, before validating anything after it, so
# `mi_ex_worst 1 2` printed 1 and exited 0. That is the failure the refusal exists to prevent —
# a caller's bug answered with a plausible-looking batch result — surviving because every existing
# test happened to place the invalid code ahead of the failure.
@test "a usage error is never aggregated, wherever it sits in the batch" {
  run mi_ex_worst 0 2
  [ "$status" -ne 0 ]
  assert_contains "usage errors are not batch outcomes"

  run mi_ex_worst 2 1
  [ "$status" -ne 0 ]
  assert_contains "usage errors are not batch outcomes"

  run mi_ex_worst 1 2
  [ "$status" -ne 0 ]
  assert_contains "usage errors are not batch outcomes"
}

@test "an empty batch is a usage error, not a success" {
  run mi_ex_worst
  [ "$status" -ne 0 ]
}

@test "an unknown code is refused rather than mapped to failure, wherever it sits in the batch" {
  run mi_ex_worst 0 7
  [ "$status" -ne 0 ]
  assert_contains "not an exit code this contract defines"

  run mi_ex_worst 7 1
  [ "$status" -ne 0 ]
  assert_contains "not an exit code this contract defines"

  run mi_ex_worst 1 7
  [ "$status" -ne 0 ]
  assert_contains "not an exit code this contract defines"
}

@test "every code has a human name, for reports" {
  run mi_ex_name 3
  assert_contains "not launched"
}
