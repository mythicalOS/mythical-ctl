#!/usr/bin/env bats
load '../lib/test_helper'
# `snapshot.sh`, WITH the extension: bats' loader tries `<slug>.bash` and then `<slug>` verbatim —
# it never appends `.sh`, so the extensionless slug resolves to nothing and the whole file aborts
# before a single test runs.
load '../harness/snapshot.sh'

setup() { setup_test_env; load_mctl; }
teardown() { teardown_test_env; }

@test "ping succeeds against the fake runtime and reports the engine version" {
  run mi_rt_ping
  [ "$status" -eq 0 ]
  run mi_rt_engine_version
  [ "$status" -eq 0 ]
  [ "$output" = "28.0.0" ]
}

@test "an engine version can be faked, so the preflight gate is testable" {
  FAKE_DOCKER_SERVER_VERSION=27.5.1 run mi_rt_engine_version
  [ "$output" = "27.5.1" ]
}

@test "ping FAILS when the daemon is unreachable" {
  # The positive control is load-bearing, not decoration. With only the negative assertion this test
  # PASSED against a repository that had no lib/runtime.sh at all: `run` on an undefined function
  # yields 127, and 127 satisfies `-ne 0`. Measured — it was one of two green tests in the pre-fix
  # run. Asserting that ping SUCCEEDS when the daemon is up cannot pass that way.
  run mi_rt_ping
  [ "$status" -eq 0 ]
  FAKE_DOCKER_DOWN=1 run mi_rt_ping
  [ "$status" -ne 0 ]
}

@test "inspect returns 3 for an absent object and 1 when the daemon cannot answer" {
  run mi_rt_inspect container c.running nope
  [ "$status" -eq 3 ]
  FAKE_DOCKER_DOWN=1 run mi_rt_inspect container c.running nope
  [ "$status" -eq 1 ]
}

@test "a caller cannot supply its own Go template" {
  run mi_rt_inspect container '{{.Config.Env}}' nope
  [ "$status" -eq 1 ]
  assert_contains "not a field this adapter exposes"
}

@test "an argument containing a control byte is refused before it reaches the runtime" {
  run mi_rt_volume_create "$(printf 'v\ta')" nonce1 inst1
  [ "$status" -ne 0 ]
  assert_contains "control byte"
}

@test "a created container is stopped, on exactly one network, with the alias" {
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  mi_rt_volume_create mythical-i1-p1-state v-nonce i1
  run mi_rt_container_create mythical-i1-p1 img@sha256:$(printf 'a%.0s' {1..64}) "$net" p1 - \
      volume=mythical-i1-p1-state:/data:rw publish=7480:7480 label=installation=i1 label=nonce=c-nonce
  [ "$status" -eq 0 ]
  run mi_rt_inspect container c.running mythical-i1-p1
  [ "$output" = "false" ]
  run mi_rt_inspect container c.nets mythical-i1-p1
  [ "$output" = "${net}=;" ]
  run mi_rt_inspect container c.aliases mythical-i1-p1
  assert_contains "${net}:p1,"
}

@test "a stopped container has NO address; starting it assigns one" {
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  mi_rt_container_create mythical-i1-p1 img@sha256:$(printf 'a%.0s' {1..64}) "$net" p1 - label=nonce=c-nonce
  run mi_rt_inspect container c.nets mythical-i1-p1
  [ "$output" = "${net}=;" ]                 # empty address, exactly as Docker reports (D48)
  mi_rt_container_start mythical-i1-p1
  run mi_rt_inspect container c.nets mythical-i1-p1
  [ "$output" != "${net}=;" ]
  mi_rt_container_stop mythical-i1-p1
  run mi_rt_inspect container c.nets mythical-i1-p1
  [ "$output" = "${net}=;" ]                 # released again on stop
}

@test "publish is ALWAYS 127.0.0.1 — a caller cannot ask for anything else" {
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  mi_rt_container_create mythical-i1-p1 img@sha256:$(printf 'a%.0s' {1..64}) "$net" p1 - publish=7480:7480 label=nonce=c
  run mi_rt_inspect container c.ports mythical-i1-p1
  assert_contains "127.0.0.1:7480"
  # -F: a literal search. As a regex, `0.0.0.0` has four wildcard dots and can match text that is
  # not the address at all. Also assert the log is non-empty first, so a wrong path cannot make the
  # absence check pass vacuously.
  [ -s "$FAKE_DOCKER_STATE/calls.log" ] || { echo "calls.log missing or empty" >&2; return 1; }
  run grep -aF -- '0.0.0.0' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
}

@test "publish=<host>:<container> is the only accepted publish shape" {
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  run mi_rt_container_create c1 img@sha256:$(printf 'a%.0s' {1..64}) "$net" p1 - publish=0.0.0.0:7480:7480 label=nonce=c
  [ "$status" -ne 0 ]
}

@test "host / none / container: network modes are refused at creation" {
  local m
  for m in host none container:other; do
    run mi_rt_container_create c1 img@sha256:$(printf 'a%.0s' {1..64}) "$m" p1 - label=nonce=c
    [ "$status" -ne 0 ]
    assert_contains "network mode"
  done
}

@test "find_by_label lists STOPPED containers too" {
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  mi_rt_container_create mythical-i1-p1 img@sha256:$(printf 'a%.0s' {1..64}) "$net" p1 - label=installation=i1 label=nonce=c
  run mi_rt_find_by_label container installation i1
  [ "$output" = "mythical-i1-p1" ]
}

@test "find_by_label rejects a label key outside the closed set" {
  run mi_rt_find_by_label container com.docker.compose.project x
  [ "$status" -ne 0 ]
  # As above: `-ne 0` alone is satisfied by 127, so this test passed with no runtime module present.
  # Pinning the refusal MESSAGE makes it fail unless the closed-set check is the thing refusing.
  assert_contains "is not a label this installer sets"
}

@test "volume create against an existing name does NOT apply labels (real semantics)" {
  mi_rt_volume_create v1 nonce-a i1
  mi_rt_volume_create v1 nonce-b i1
  run mi_rt_inspect volume v.nonce v1
  [ "$output" = "nonce-a" ]
}

@test "network create can be made to produce a duplicate, so D38 is testable" {
  a="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  # MEASURED: `VAR=1 b="$(cmd)"` is an ASSIGNMENT LIST, not an env-prefixed command — VAR becomes an
  # unexported shell variable and the fake `docker`, an external program, never sees it. (The
  # `VAR=1 run …` form used elsewhere in this file DOES work: `run` is a function, and bash exports
  # the prefix for the duration of the call. Both measured on this machine.) So: export explicitly.
  export FAKE_DOCKER_NET_DUPLICATE=1
  b="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  unset FAKE_DOCKER_NET_DUPLICATE
  [ "$a" != "$b" ]
  run mi_rt_find_by_label network installation i1
  [ "$(printf '%s\n' "$output" | wc -l | tr -d ' ')" = 2 ]
}

@test "image pull failures are distinguishable" {
  local o
  for o in notfound auth neterr; do
    FAKE_DOCKER_PULL="$o" run mi_rt_image_pull "img@sha256:$(printf 'a%.0s' {1..64})"
    [ "$status" -ne 0 ]
  done
  run mi_rt_image_pull "img@sha256:$(printf 'a%.0s' {1..64})"
  [ "$status" -eq 0 ]
}

@test "snap_runtime captures containers and networks, not only volumes" {
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  mi_rt_volume_create mythical-i1-p1-state v-nonce i1
  mi_rt_container_create mythical-i1-p1 img@sha256:$(printf 'a%.0s' {1..64}) "$net" p1 - label=nonce=c
  snap_runtime "$BATS_TEST_TMPDIR/r1"
  run grep -ac . "$BATS_TEST_TMPDIR/r1"
  [ "$output" = "3" ]                        # exactly the network, the volume and the container
  run grep -a '^container' "$BATS_TEST_TMPDIR/r1"
  [ "$status" -eq 0 ]
  run grep -a '^network' "$BATS_TEST_TMPDIR/r1"
  [ "$status" -eq 0 ]
  run grep -a '^volume' "$BATS_TEST_TMPDIR/r1"
  [ "$status" -eq 0 ]
}
