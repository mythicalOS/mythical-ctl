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

@test "fs snapshot is stable across a no-op and detects a new file" {
  load_mctl; mi_ensure_layout
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  snap_fs "$BATS_TEST_TMPDIR/a"
  snap_fs "$BATS_TEST_TMPDIR/b"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/b"
  assert_ok
  echo hello > "$MYTHICAL_HOME/brokkr.conf"
  snap_fs "$BATS_TEST_TMPDIR/c"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/c"
  [ "$status" -eq 1 ]
  assert_contains "brokkr.conf"
}

@test "fs snapshot detects an in-place content change with the SAME mode" {
  load_mctl; mi_ensure_layout
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  echo one > "$MYTHICAL_HOME/brokkr.conf"; chmod 600 "$MYTHICAL_HOME/brokkr.conf"
  snap_fs "$BATS_TEST_TMPDIR/a"
  echo two > "$MYTHICAL_HOME/brokkr.conf"; chmod 600 "$MYTHICAL_HOME/brokkr.conf"  # same mode, new bytes
  snap_fs "$BATS_TEST_TMPDIR/b"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/b"
  [ "$status" -eq 1 ]
  assert_contains "brokkr.conf"
}

@test "fs snapshot is robust to a filename containing a newline and a tab" {
  load_mctl; mi_ensure_layout
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  # A user-data file whose name contains a newline AND a tab must not split or corrupt the snapshot:
  # exactly one line per entry, stable across a no-op, and its content change is still detected.
  printf 'x' > "$MYTHICAL_HOME/weird"$'\n'"na"$'\t'"me"
  snap_fs "$BATS_TEST_TMPDIR/a"
  # the weird name must appear on EXACTLY ONE line, escaped (no split into false paths). -F: the
  # pattern is the literal escaped form `weird\nna\tme` (backslash-n, backslash-t) that _snap_enc writes.
  [ "$(grep -Fc 'weird\nna\tme' "$BATS_TEST_TMPDIR/a")" -eq 1 ]
  snap_fs "$BATS_TEST_TMPDIR/b"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/b"
  assert_ok
  printf 'CHANGED' > "$MYTHICAL_HOME/weird"$'\n'"na"$'\t'"me"
  snap_fs "$BATS_TEST_TMPDIR/c"
  run snap_assert_unchanged "$BATS_TEST_TMPDIR/a" "$BATS_TEST_TMPDIR/c"
  [ "$status" -eq 1 ]
}

@test "fs snapshot does not hang on a FIFO — special files are recorded, never read" {
  load_mctl; mi_ensure_layout
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  # A named pipe in user data must not be hashed (a reader would block forever). It is recorded by
  # type instead, so the snapshot completes. `run` fails the test if snap_fs hangs (bats times out).
  mkfifo "$MYTHICAL_HOME/apipe"
  run snap_fs "$BATS_TEST_TMPDIR/a"
  assert_ok
  grep -qE '/apipe	special	' "$BATS_TEST_TMPDIR/a"
}

@test "runtime snapshot captures volumes and their labels" {
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  docker volume create --label mythical.nonce=n1 vol-x
  snap_runtime "$BATS_TEST_TMPDIR/r"
  grep -q 'vol-x' "$BATS_TEST_TMPDIR/r"
  grep -q 'mythical.nonce=n1' "$BATS_TEST_TMPDIR/r"
}

@test "the lock file and its temps (incl. the recovery gate) are excluded from the fs snapshot" {
  load_mctl; mi_ensure_layout; mi_lock_acquire
  # A normal acquire creates no recovery/temp files, so plant the transient artifacts a stale-break
  # leaves mid-flight — the recovery gate, its mktemp publish temp, and the lock's publish temp.
  # None may appear in a snapshot.
  : > "$MYTHICAL_HOME/.state/lock.recovery"
  : > "$MYTHICAL_HOME/.state/lock.recovery.AbC123"
  : > "$MYTHICAL_HOME/.state/lock.new.abc123"
  source "$_MCTL_ROOT/tests/harness/snapshot.sh"
  snap_fs "$BATS_TEST_TMPDIR/s"
  ! grep -q '\.state/lock' "$BATS_TEST_TMPDIR/s"
  rm -f "$MYTHICAL_HOME"/.state/lock.recovery* "$MYTHICAL_HOME"/.state/lock.new.*
  mi_lock_release
}
