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

@test "the engine version is read from the SERVER, not from the client" {
  # `docker version` reports BOTH, and the fake used to answer any template with the server's number
  # — so `{{.Client.Version}}` would have looked correct and D29's engine-28 floor would have been
  # comparing the CLI's own version, which says nothing about the daemon. The two are deliberately
  # far apart here: a client that would pass the floor in front of a daemon that would not.
  FAKE_DOCKER_CLIENT_VERSION=99.9.9 FAKE_DOCKER_SERVER_VERSION=24.0.9 run mi_rt_engine_version
  [ "$status" -eq 0 ]
  [ "$output" = "24.0.9" ] \
    || { echo "engine version reported as '$output' — that is not the SERVER's" >&2; return 1; }
}

@test "rootless is read from the daemon's SecurityOptions, and 'cannot ask' is not 'rootful'" {
  # §4b.2 refuses a rootless daemon, and the three answers are three different postures: 0 rootless,
  # 1 rootful, 2 the daemon could not be asked. A caller writing `if mi_rt_rootless; then refuse; fi`
  # gets the right answer for 1 and silently the WRONG posture for 2, so 2 has to stay distinct.
  run mi_rt_rootless
  [ "$status" -eq 1 ] || { echo "an ordinary daemon reported rootless status $status" >&2; return 1; }
  FAKE_DOCKER_ROOTLESS=1 run mi_rt_rootless
  [ "$status" -eq 0 ] || { echo "a rootless daemon reported status $status" >&2; return 1; }
  FAKE_DOCKER_DOWN=1 run mi_rt_rootless
  [ "$status" -eq 2 ] \
    || { echo "an unreachable daemon reported status $status, not the distinct 2" >&2; return 1; }
}

@test "the daemon endpoint is read from the active context (D30)" {
  # D30 refuses a REMOTE daemon: bind sources resolve on the daemon's host, so a remote one validates
  # the wrong filesystem. The fake used to print the endpoint for every template, so this could have
  # been reading any field of the context document at all.
  run mi_rt_context_host
  [ "$status" -eq 0 ]
  [ "$output" = "unix:///var/run/docker.sock" ] \
    || { echo "local endpoint reported as '$output'" >&2; return 1; }
  FAKE_DOCKER_CONTEXT_HOST=ssh://user@elsewhere run mi_rt_context_host
  [ "$output" = "ssh://user@elsewhere" ] \
    || { echo "remote endpoint reported as '$output'" >&2; return 1; }
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

@test "the family network is created with an EXPLICIT bridge driver (D29)" {
  # `--driver bridge` is a security guard, and the ordinary assertion cannot pin it: `bridge` is
  # ALREADY the daemon's default, so a network created with the flag and one created without it look
  # identical. Deleting the flag would leave `n.driver` reporting `bridge` and the suite green —
  # which is how the flag came to be untestable in the first place.
  #
  # So the second half of this test asks the question the guard exists to answer. D29's stated threat
  # is "a daemon-level default change silently removes the NAT wall"; the fake is told to default to
  # something that is not a NAT bridge, and the adapter's network must STILL be a bridge, which it can
  # only be if the adapter named the driver itself.
  local net other
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  run mi_rt_inspect network n.driver "$net"
  [ "$status" -eq 0 ]
  [ "$output" = "bridge" ] \
    || { echo "the family network's driver is '$output', not bridge" >&2; return 1; }

  export FAKE_DOCKER_NET_DEFAULT_DRIVER=macvlan   # a daemon whose default is not a NAT bridge
  other="$(mi_rt_network_create mythical-i2-net i2 n-nonce)"
  unset FAKE_DOCKER_NET_DEFAULT_DRIVER
  run mi_rt_inspect network n.driver "$other"
  [ "$output" = "bridge" ] \
    || { echo "with a non-bridge daemon default the family network came out '$output' — the adapter is relying on the default, not naming the driver" >&2; return 1; }
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

@test "the helper container is always --rm — no helper outlives its own invocation" {
  # D49/D54: a pinned helper runs and is gone. The fake recorded no container for a `run` at all, so
  # `--rm` could be deleted from the adapter with nothing left behind for any test to find. Now a run
  # without it leaves one, exactly as a real daemon does — which is what makes the flag observable.
  local img
  img="$(pulled_image)"
  fake_helper 'exit 0'
  run mi_rt_run_helper "$img" none - n1 selfcheck
  [ "$status" -eq 0 ]
  run docker container ls -a --format '{{.Names}}'
  [ -z "$output" ] \
    || { echo "the helper left a container behind: $output" >&2; return 1; }
}

@test "container rm force-removes a RUNNING container" {
  # `-f` was parsed and discarded by the fake, so `container rm -f` and `container rm` were the same
  # call and the flag could have been dropped with the suite green. Reconciliation cannot clear a
  # live container without it.
  local net
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  mi_rt_container_create mythical-i1-p1 "$(pulled_image)" "$net" p1 - label=nonce=c
  mi_rt_container_start mythical-i1-p1
  run mi_rt_inspect container c.running mythical-i1-p1
  [ "$output" = "true" ] || { echo "the container is not running: $output" >&2; return 1; }
  run mi_rt_container_rm mythical-i1-p1
  [ "$status" -eq 0 ] \
    || { echo "a running container could not be removed — is -f still passed? $output" >&2; return 1; }
  run mi_rt_inspect container c.running mythical-i1-p1
  [ "$status" -eq 3 ] || { echo "the container survived removal (rc $status)" >&2; return 1; }
}

@test "connect passes the alias EXPLICITLY, so a sibling can reach the peer (§6b.2)" {
  # `docker network connect` infers no alias of its own; without one the container is reachable only
  # under its installation-scoped NAME, which no sibling can guess — family DNS then fails silently,
  # indistinguishable from an absent peer (§9). The fake recorded an empty alias list either way, so
  # the flag was invisible; it now always records the automatic name alias, and the explicit one
  # beside it when there is one.
  local net net2
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  net2="$(mi_rt_network_create mythical-i1-net2 i1 n-nonce)"
  mi_rt_container_create mythical-i1-p1 "$(pulled_image)" "$net" p1 - label=nonce=c
  run mi_rt_network_connect "$net2" mythical-i1-p1 p1 0
  [ "$status" -eq 0 ]
  run mi_rt_inspect container c.aliases mythical-i1-p1
  case "$output" in
    *"${net2}:p1,"*) : ;;
    *) echo "the peer alias 'p1' is not on the attachment: $output" >&2; return 1 ;;
  esac
}

@test "an env file that does not exist is refused by the ADAPTER, before the runtime" {
  # §4.3: bootstrap secrets go in a per-container 0600 env file, never in argv. Launching without the
  # file the caller named is not a detail, and the refusal must come from the adapter — the message
  # is pinned, because the fake now refuses a missing env file too (in the CLI's words) and a
  # status-only assertion would pass on that instead.
  local net
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  run mi_rt_container_create c1 "$(pulled_image)" "$net" p1 "${BATS_TEST_TMPDIR}/absent.env" label=nonce=c
  [ "$status" -ne 0 ]
  assert_contains "does not exist"
  # Nothing reached the runtime at all.
  run grep -aF -- "absent.env" "$FAKE_DOCKER_STATE/calls.log"
  [ "$status" -ne 0 ] || { echo "the missing env file reached the runtime" >&2; return 1; }
  # A file that exists is accepted, so the refusal is about existence and nothing else.
  : > "${BATS_TEST_TMPDIR}/present.env"
  run mi_rt_container_create c1 "$(pulled_image)" "$net" p1 "${BATS_TEST_TMPDIR}/present.env" label=nonce=c
  [ "$status" -eq 0 ]
}

@test "gateway priority must be an integer, not merely made of integer characters" {
  # `case "$gw" in ''|*[!0-9-]*)` constrains the character SET only, so every value below passed it
  # and reached `docker network connect --gw-priority`.
  local bad net2 net3
  net="$(mi_rt_network_create mythical-i1-net i1 n-nonce)"
  mi_rt_container_create mythical-i1-p1 "$(pulled_image)" "$net" p1 - label=nonce=c
  for bad in '1-2' '-' '--' '5-' '1-2-3'; do
    run mi_rt_network_connect "$net" mythical-i1-p1 p1 "$bad"
    [ "$status" -ne 0 ] \
      || { echo "gateway priority '$bad' was accepted" >&2; return 1; }
    assert_contains "is not an integer"
  done
  # The two legitimate shapes still work: D45 phase 2 needs a NEGATIVE priority to be expressible.
  #
  # Each positive control uses a network the container is NOT already on. The original fixture
  # connected it twice to the network it was CREATED on, which a real daemon refuses ("endpoint with
  # name … already exists in network …") — the fake accepted it and grew a duplicate attachment. The
  # assertions are unchanged; only the fixture is, because the old one could not have run against a
  # real daemon at all.
  net2="$(mi_rt_network_create mythical-i1-net2 i1 n-nonce)"
  net3="$(mi_rt_network_create mythical-i1-net3 i1 n-nonce)"
  run mi_rt_network_connect "$net2" mythical-i1-p1 p1 10
  [ "$status" -eq 0 ]
  run mi_rt_network_connect "$net3" mythical-i1-p1 p1 -20
  [ "$status" -eq 0 ]
}
