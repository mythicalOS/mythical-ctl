#!/usr/bin/env bats
load '../lib/test_helper'
# `snapshot.sh`, WITH the extension: bats' loader tries `<slug>.bash` and then `<slug>` verbatim —
# it never appends `.sh`, so the extensionless slug resolves to nothing and the whole file aborts
# before a single test runs.
load '../harness/snapshot.sh'

setup() { setup_test_env; load_mctl; }
teardown() { teardown_test_env; }

# The fake now refuses `container create`/`container run` from an image it was never asked to pull,
# because that is what a real daemon does. Every test that reaches the runtime therefore pulls first
# — which is the point of the change, not a workaround for it: a task that forgets to pull must fail
# here rather than against a real daemon. `$(…)` is a subshell, but the pull's effect is a file under
# $FAKE_DOCKER_STATE, so it survives.
pulled_image() {
  local ref="img@sha256:$(printf 'a%.0s' {1..64})"
  mi_rt_image_pull "$ref" >/dev/null
  printf '%s' "$ref"
}

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
  run mi_rt_container_create mythical-i1-p1 "$(pulled_image)" "$net" p1 - \
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
  mi_rt_container_create mythical-i1-p1 "$(pulled_image)" "$net" p1 - label=nonce=c-nonce
  run mi_rt_inspect container c.nets mythical-i1-p1
  [ "$output" = "${net}=;" ]                 # empty address, exactly as Docker reports (D48)
  mi_rt_container_start mythical-i1-p1
  run mi_rt_inspect container c.nets mythical-i1-p1
  [ "$output" != "${net}=;" ]
  mi_rt_container_stop mythical-i1-p1
  run mi_rt_inspect container c.nets mythical-i1-p1
  [ "$output" = "${net}=;" ]                 # released again on stop
}

@test "EVERY published port is on 127.0.0.1 — a caller cannot ask for anything else" {
  # TWO mappings, and the COMPLETE inspect value is asserted. This is the module's single most
  # load-bearing invariant (D26/§4b.1) and it was pinned by a substring: an adapter emitting both
  # `-p 127.0.0.1:7480:7480` and `-p 192.0.2.1:9999:9443` satisfies "contains 127.0.0.1", and the
  # `0.0.0.0`-absence check does not notice a different non-loopback address either. "A port is
  # loopback" is not the claim; "every port is loopback" is.
  local ent hostip
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  mi_rt_container_create mythical-i1-p1 "$(pulled_image)" "$net" p1 - \
      publish=7480:7480 publish=9999:9443 label=nonce=c
  run mi_rt_inspect container c.ports mythical-i1-p1
  [ "$output" = "7480/tcp=127.0.0.1:7480;9443/tcp=127.0.0.1:9999;" ] \
    || { echo "unexpected complete port map: $output" >&2; return 1; }
  # And independently of that literal: every host IP in the map, whatever the map turns out to be.
  # A stricter reading of the same invariant, so a future record-format change cannot quietly turn
  # the equality above into the only thing being checked.
  for ent in $(printf '%s' "$output" | tr ';' ' '); do
    hostip="${ent#*=}"; hostip="${hostip%:*}"
    [ "$hostip" = "127.0.0.1" ] \
      || { echo "published on a non-loopback host IP: $hostip (in $output)" >&2; return 1; }
  done
  # -F: a literal search. As a regex, `0.0.0.0` has four wildcard dots and can match text that is
  # not the address at all. Also assert the log is non-empty first, so a wrong path cannot make the
  # absence check pass vacuously.
  [ -s "$FAKE_DOCKER_STATE/calls.log" ] || { echo "calls.log missing or empty" >&2; return 1; }
  run grep -aF -- '0.0.0.0' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
}

@test "publish=<host>:<container> is the only accepted publish shape" {
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  # The image is deliberately NOT pulled here, and the refusal MESSAGE is pinned: this spec must be
  # rejected by the adapter before the runtime is reached at all. With `-ne 0` alone, a weakened
  # adapter that let the spec through would now fail anyway — on the fake's absent-image gate — and
  # the test would stay green while proving nothing about the publish grammar.
  run mi_rt_container_create c1 img@sha256:$(printf 'a%.0s' {1..64}) "$net" p1 - publish=0.0.0.0:7480:7480 label=nonce=c
  [ "$status" -ne 0 ]
  assert_contains "publish host port '0.0.0.0' is not a port"
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
  mi_rt_container_create mythical-i1-p1 "$(pulled_image)" "$net" p1 - label=installation=i1 label=nonce=c
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
  # DISTINGUISHABLE is the claim, so the registry's own words are what gets asserted. Checking only
  # `-ne 0` per outcome is satisfied by an implementation that folds all three into one generic
  # message — which §7.3/§10a specifically forbid, and which is exactly the failure this test's name
  # promises to catch. `run` merges stderr into $output, and mi_rt_image_pull passes the registry's
  # stderr through by design, so the words are visible here.
  local ref="img@sha256:$(printf 'a%.0s' {1..64})"
  FAKE_DOCKER_PULL=notfound run mi_rt_image_pull "$ref"
  [ "$status" -ne 0 ]
  assert_contains "manifest unknown"
  FAKE_DOCKER_PULL=auth run mi_rt_image_pull "$ref"
  [ "$status" -ne 0 ]
  assert_contains "requested access to the resource is denied"
  FAKE_DOCKER_PULL=neterr run mi_rt_image_pull "$ref"
  [ "$status" -ne 0 ]
  assert_contains "no such host"
  run mi_rt_image_pull "$ref"
  [ "$status" -eq 0 ]
}

@test "snap_runtime captures containers and networks, not only volumes" {
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  mi_rt_volume_create mythical-i1-p1-state v-nonce i1
  mi_rt_container_create mythical-i1-p1 "$(pulled_image)" "$net" p1 - label=nonce=c
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

# --- the mount grammar: a comma is a SEPARATOR, not a character ------------------------------------
# `--mount` takes a comma-separated key=value list. Splitting a spec only on `:` and checking
# "absolute" and "no .." lets any component carry `,<key>=<value>` straight into Docker's own mount
# grammar. Both specs below were run against the pre-fix adapter and both reached the runtime.

@test "a comma in a bind spec cannot smuggle a Docker mount option" {
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  # Pre-fix, MEASURED: target=[/container,bind-propagation=rshared] passed the absolute-path check
  # and the emitted argv was
  #   --mount type=bind,source=/host,target=/container,bind-propagation=rshared
  run mi_rt_container_create c1 "$(pulled_image)" "$net" p1 - \
      'bind=/host:/container,bind-propagation=rshared:rw' label=nonce=c
  [ "$status" -ne 0 ]
  assert_contains "contains a comma"
  # The refusal must name the offending spec, and nothing may have reached the runtime.
  assert_contains "bind=/host:/container,bind-propagation=rshared:rw"
  run grep -aF -- 'bind-propagation' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
  # A comma in the SOURCE half is the same hole from the other side.
  run mi_rt_container_create c1 "$(pulled_image)" "$net" p1 - \
      'bind=/host,bind-propagation=rshared:/container:rw' label=nonce=c
  [ "$status" -ne 0 ]
  assert_contains "contains a comma"
}

@test "a comma in a volume spec cannot convert a named volume into a host bind" {
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  # The worse half of the same defect. Pre-fix, MEASURED, the emitted argv was
  #   --mount type=volume,source=v,volume-opt=o=bind,volume-opt=device=/etc,target=/d
  # i.e. a container escape expressed through the one API whose purpose is to make an unsafe launch
  # inexpressible.
  run mi_rt_container_create c1 "$(pulled_image)" "$net" p1 - \
      'volume=v,volume-opt=o=bind,volume-opt=device=/etc:/d:rw' label=nonce=c
  [ "$status" -ne 0 ]
  assert_contains "contains a comma"
  run grep -aF -- 'volume-opt' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
  # And a volume SOURCE is a name, never a path: `/etc` as a "volume name" is a bind in disguise.
  run mi_rt_container_create c1 "$(pulled_image)" "$net" p1 - 'volume=/etc:/d:rw' label=nonce=c
  [ "$status" -ne 0 ]
  assert_contains "not a volume name"
}

@test "the helper's three mount specs are validated, not interpolated" {
  local p
  p="$(pulled_image)"
  # `staging=` is the helper's ONE writable mount, and a later task passes an operator-influenced
  # destination through it. Pre-fix these three were interpolated raw, with no check of any kind:
  #   staging=/host,bind-propagation=rshared
  #     → --mount type=bind,source=/host,bind-propagation=rshared,target=/dst
  run mi_rt_run_helper "$p" none - n1 copy 'staging=/host,bind-propagation=rshared'
  [ "$status" -ne 0 ]
  assert_contains "contains a comma"
  run mi_rt_run_helper "$p" none - n1 copy 'dstro=/host,bind-propagation=rshared'
  [ "$status" -ne 0 ]
  assert_contains "contains a comma"
  run mi_rt_run_helper "$p" none - n1 copy 'srcvol=v,volume-opt=device=/etc'
  [ "$status" -ne 0 ]
  assert_contains "contains a comma"
  run grep -aF -- 'bind-propagation' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
  run grep -aF -- 'volume-opt' "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ]
  # A bind source resolves on the DAEMON's host, so a relative one names an unpredictable directory.
  run mi_rt_run_helper "$p" none - n1 copy 'staging=relative/path'
  [ "$status" -ne 0 ]
  assert_contains "is not absolute"
  run mi_rt_run_helper "$p" none - n1 copy 'staging=/staged/../../etc'
  [ "$status" -ne 0 ]
  assert_contains "contains a .. component"
}

@test "a container cannot be created from an image that was never pulled" {
  # Real Docker attempts a pull and then errors; it does not create the container. A fake that
  # records it regardless lets a later task that forgot to pull pass here and fail against a real
  # daemon, and makes §10a's "not launched ⇒ no pull attempted" row unprovable.
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  run mi_rt_container_create c1 "img@sha256:$(printf 'b%.0s' {1..64})" "$net" p1 - label=nonce=c
  [ "$status" -ne 0 ]
  assert_contains "Unable to find image"
  [ ! -e "$FAKE_DOCKER_STATE/containers/c1" ] \
    || { echo "the refused create still recorded a container" >&2; return 1; }
  # Same gate on the helper path, which is `container run`.
  run mi_rt_run_helper "img@sha256:$(printf 'b%.0s' {1..64})" none - n1 selfcheck
  [ "$status" -ne 0 ]
  assert_contains "Unable to find image"
  # After a pull, the very same create succeeds — so the refusal is the image gate, not the spec.
  run mi_rt_container_create c1 "$(pulled_image)" "$net" p1 - label=nonce=c
  [ "$status" -eq 0 ]
}

@test "a bind whose source does not exist is refused, never silently created" {
  # This is the stated reason lib/runtime.sh uses `--mount type=bind` instead of `-v`: -v CREATES a
  # missing source as a directory, which is how a single-file bind stops being the file the product
  # writes. Until the fake enforced it, that guarantee was asserted by nothing.
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  run mi_rt_container_create c1 "$(pulled_image)" "$net" p1 - \
      "bind=${BATS_TEST_TMPDIR}/absent/conf:/etc/p.conf:ro" label=nonce=c
  [ "$status" -ne 0 ]
  assert_contains "bind source path does not exist"
  [ ! -e "$FAKE_DOCKER_STATE/containers/c1" ] \
    || { echo "the refused create still recorded a container" >&2; return 1; }
  [ ! -e "${BATS_TEST_TMPDIR}/absent/conf" ] \
    || { echo "the runtime created the missing bind source" >&2; return 1; }
  # An existing source is accepted, so the refusal is about existence and nothing else.
  mkdir -p "${BATS_TEST_TMPDIR}/present"; : > "${BATS_TEST_TMPDIR}/present/conf"
  run mi_rt_container_create c1 "$(pulled_image)" "$net" p1 - \
      "bind=${BATS_TEST_TMPDIR}/present/conf:/etc/p.conf:ro" label=nonce=c
  [ "$status" -eq 0 ]
}

@test "gateway priority must be an integer, not merely made of integer characters" {
  # `case "$gw" in ''|*[!0-9-]*)` constrains the character SET only, so every value below passed it
  # and reached `docker network connect --gw-priority`.
  local bad
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  mi_rt_container_create mythical-i1-p1 "$(pulled_image)" "$net" p1 - label=nonce=c
  for bad in '1-2' '-' '--' '5-' '1-2-3'; do
    run mi_rt_network_connect "$net" mythical-i1-p1 p1 "$bad"
    [ "$status" -ne 0 ] \
      || { echo "gateway priority '$bad' was accepted" >&2; return 1; }
    assert_contains "is not an integer"
  done
  # The two legitimate shapes still work: D45 phase 2 needs a NEGATIVE priority to be expressible.
  run mi_rt_network_connect "$net" mythical-i1-p1 p1 10
  [ "$status" -eq 0 ]
  run mi_rt_network_connect "$net" mythical-i1-p1 p1 -20
  [ "$status" -eq 0 ]
}
