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

# --- resource names are path components, so they are the fake's own attack surface ----------------
# Re-point the fake's state INSIDE bats' per-test tmpdir, so a `../../` escape lands in a tree bats
# removes after the test and the assertions can name the exact escaped path. $STATE/<kind>/../../x
# resolves to the state directory's PARENT, which is $ESC below.
# The original mktemp state dir is removed first, so nothing leaks even if the test fails early.
relocate_fake_state() {
  rm -rf "$FAKE_DOCKER_STATE"
  FAKE_DOCKER_STATE="$BATS_TEST_TMPDIR/fake/state"
  export FAKE_DOCKER_STATE
  mkdir -p "$FAKE_DOCKER_STATE"
  ESC="$BATS_TEST_TMPDIR/fake"
}

@test "a name that traverses out of the state directory is refused for every resource kind" {
  # MEASURED against the pre-fix fake: `docker network create ../../x` resolved to
  # $FAKE_DOCKER_STATE/networks/../../x and CREATED a file outside the fake's own state directory —
  # test isolation gone, and the fake materially MORE PERMISSIVE than the real daemon, which refuses
  # such names outright. That is the one thing this file must never be.
  local before after
  relocate_fake_state
  # The container attempt must be one that would otherwise SUCCEED, so its refusal can only be the
  # name rule: the image is pulled and the network exists first.
  docker image pull demo/img:tag >/dev/null
  net="$(docker network create n1)"
  before="$(ls -a "$ESC")"

  run docker network create ../../escapee-network
  [ "$status" -ne 0 ] || { echo "network create accepted a traversing name" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  run docker volume create ../../escapee-volume
  [ "$status" -ne 0 ] || { echo "volume create accepted a traversing name" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  run docker container create --name ../../escapee-container --network "$net" -- demo/img:tag
  [ "$status" -ne 0 ] || { echo "container create accepted a traversing name" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'

  # Per kind, and then over the whole directory: an escape under ANY other name is caught too.
  [ ! -e "$ESC/escapee-network" ]   || { echo "network create wrote outside the state dir" >&2; return 1; }
  [ ! -e "$ESC/escapee-volume" ]    || { echo "volume create wrote outside the state dir" >&2; return 1; }
  [ ! -e "$ESC/escapee-container" ] || { echo "container create wrote outside the state dir" >&2; return 1; }
  after="$(ls -a "$ESC")"
  [ "$before" = "$after" ] \
    || { echo "the state directory's parent changed:"; diff <(echo "$before") <(echo "$after"); return 1; }
}

@test "a traversing name cannot read or rewrite a file that already exists outside the state dir" {
  # The other half of the escape, and the more alarming one: a name that resolves onto an EXISTING
  # file makes the fake treat that file as one of its own records. All three MEASURED against the
  # pre-fix fake, with the file holding 'IMPORTANT DATA':
  #
  #   docker volume create  ../../canary → rc 0   ("existing volume" — the outside file is adopted)
  #   docker volume inspect ../../canary → rc 0   ({ "Name": "../../canary", … } — outside file read)
  #   docker container start ../../canary → rc 0  and rec_set's `mv -f` REWROTE the file, which then
  #                                               read: IMPORTANT DATA / state=running / nets=
  local body
  relocate_fake_state
  printf 'IMPORTANT DATA\n' > "$ESC/canary"

  run docker volume create ../../canary
  [ "$status" -ne 0 ] || { echo "volume create adopted a file outside the state dir" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  run docker volume inspect ../../canary
  [ "$status" -ne 0 ] || { echo "volume inspect read a file outside the state dir: $output" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  run docker container start ../../canary
  [ "$status" -ne 0 ] || { echo "container start acted on a file outside the state dir" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'

  body="$(cat "$ESC/canary")"
  [ "$body" = "IMPORTANT DATA" ] \
    || { echo "a file outside the state directory was rewritten: $body" >&2; return 1; }
  # And no mktemp publish temp was left there either — rec_set builds its temp beside its target.
  [ "$(ls -A "$ESC" | grep -ac .)" = 2 ] \
    || { echo "unexpected entries beside the state dir: $(ls -A "$ESC")" >&2; return 1; }
}

@test "every subcommand that takes a name validates it, not only create" {
  # A rule applied only at create is a rule with a door beside it: inspect, rm, start, stop, connect
  # and disconnect all spell their argument into the same directory.
  local sub
  relocate_fake_state
  for sub in "volume inspect" "volume rm" "network inspect" "network rm" \
             "container inspect" "container rm" "container start" "container stop"; do
    # Deliberate word split: $sub is a two-word subcommand.
    run docker $sub ../../escapee
    [ "$status" -ne 0 ] || { echo "docker $sub accepted a traversing name" >&2; return 1; }
    assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  done
  run docker network connect --alias a --gw-priority 0 -- ../../escapee c1
  [ "$status" -ne 0 ] || { echo "network connect accepted a traversing network" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  run docker network disconnect -- n1 ../../escapee
  [ "$status" -ne 0 ] || { echo "network disconnect accepted a traversing container" >&2; return 1; }
  assert_contains '[a-zA-Z0-9][a-zA-Z0-9_.-]'
  [ ! -e "$ESC/escapee" ] || { echo "a lookup wrote outside the state dir" >&2; return 1; }
  # The EMPTY name is the same defect wearing nothing: `$STATE/containers/` is the containers
  # DIRECTORY, `[ -e ]` accepts it, and the pre-fix fake rendered a field from it and exited 0.
  run docker container inspect --format '{{.Id}}' -- ""
  [ "$status" -ne 0 ] || { echo "container inspect accepted an empty name (output: '$output')" >&2; return 1; }
}

@test "image records are keyed by the exact reference, not a character-folded one" {
  # `tr -c 'A-Za-z0-9._-' '_'` folded `foo/bar:tag` and `foo_bar:tag` to the SAME key `foo_bar_tag`,
  # so pulling one satisfied the create/run image gate for the other and that gate stopped meaning
  # "this image was pulled". Real Docker treats them as different repositories.
  local net
  net="$(docker network create n1)"
  docker image pull foo/bar:tag >/dev/null

  run docker image inspect --format '{{index .RepoDigests 0}}' -- foo_bar:tag
  [ "$status" -ne 0 ] || { echo "an unpulled reference inspected as present: $output" >&2; return 1; }
  assert_contains "No such image: foo_bar:tag"
  run docker container create --name c1 --network "$net" -- foo_bar:tag
  [ "$status" -ne 0 ] || { echo "create accepted an image that was never pulled" >&2; return 1; }
  assert_contains "Unable to find image 'foo_bar:tag' locally"
  [ ! -e "$FAKE_DOCKER_STATE/containers/c1" ] \
    || { echo "the refused create still recorded a container" >&2; return 1; }
  run docker container run --rm --network none -- foo_bar:tag selfcheck
  [ "$status" -ne 0 ] || { echo "run accepted an image that was never pulled" >&2; return 1; }
  assert_contains "Unable to find image 'foo_bar:tag' locally"
  # The reference that WAS pulled still resolves, so the new key did not simply break every lookup.
  run docker container create --name c2 --network "$net" -- foo/bar:tag
  assert_ok
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
