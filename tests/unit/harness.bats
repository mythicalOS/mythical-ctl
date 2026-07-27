load '../lib/test_helper'

@test "fake docker records and inspects a labelled volume, with no Id" {
  docker volume create --label mythical.nonce=n1 vol-a
  run docker volume inspect vol-a
  assert_ok
  assert_contains '"Name": "vol-a"'
  assert_contains 'mythical.nonce=n1'
  case "$output" in *'"Id"'*) echo "volumes must not report an Id"; return 1;; esac
}

@test "creating an existing volume does not overwrite labels (real semantics)" {
  docker volume create --label mythical.nonce=n1 vol-b
  docker volume create --label mythical.nonce=n2 vol-b   # must NOT change the label
  run docker volume inspect vol-b
  assert_contains 'mythical.nonce=n1'
  case "$output" in *n2*) echo "existing volume label was overwritten"; return 1;; esac
}

@test "pull outcome is programmable" {
  FAKE_DOCKER_PULL=notfound run docker image pull ghcr.io/x/y@sha256:deadbeef
  [ "$status" -ne 0 ]
  assert_contains "not found"
  FAKE_DOCKER_PULL=ok run docker image pull ghcr.io/x/y@sha256:deadbeef
  assert_ok
}

@test "every call is logged" {
  docker volume create vol-c
  docker volume rm vol-c
  grep -q 'volume create' "$FAKE_DOCKER_STATE/calls.log"
  grep -q 'volume rm'     "$FAKE_DOCKER_STATE/calls.log"
}

@test "info reports a programmable server version" {
  FAKE_DOCKER_SERVER_VERSION=27.1.0 run docker info --format '{{.ServerVersion}}'
  assert_contains "27.1.0"
}
